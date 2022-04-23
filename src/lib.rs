use std::{
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use actix_service::{Service, Transform};
use actix_web::{
    body::MessageBody,
    cookie::{Cookie, CookieJar, Key, SameSite},
    dev::{Payload, ServiceRequest, ServiceResponse},
    error::{ErrorInternalServerError, ErrorUnauthorized},
    http::header::{HeaderValue, SET_COOKIE},
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse,
};
use bitflags::bitflags;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use mongodb::{
    bson,
    bson::{doc, Uuid},
    Client,
};
use serde::{Deserialize, Serialize};

const COOKIE_NAME: &str = "uid";

bitflags! {
    #[rustfmt::skip]
    pub struct Permissions: i32 {
        const ADMIN =   0b00000001;
        const INVITE =  0b00000010;
        const CLIP =    0b00000100;
        const RECEPT =  0b00001000;
    }
}

bitflags_serde_shim::impl_serde_for_bitflags!(Permissions);

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: i64,
    pub permissions: Permissions,
    #[serde(skip_serializing)]
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct SessionData {
    uid: Uuid,
    created_at: u64,
}

impl SessionData {
    fn new(uid: Uuid) -> Self {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        Self {
            uid,
            created_at: since_the_epoch.as_secs(),
        }
    }
}

pub fn parse_user(doc: bson::document::Document) -> Result<User, bson::de::Error> {
    bson::from_bson(bson::Bson::Document(doc))
}

impl FromRequest for User {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let extensions = req.extensions();
        let internal_session = match extensions.get::<InternalSession>() {
            Some(internal_session) => internal_session,
            None => {
                return Box::pin(async move {
                    Err(ErrorInternalServerError("unable to get indentifier"))
                })
            }
        };

        let users = internal_session.client.database("auth").collection("users");
        let session_data = internal_session.session_data;

        Box::pin(async move {
            let session_data = match session_data {
                Some(data) => data,
                None => return Err(ErrorUnauthorized("not logged in")),
            };

            let result = users.find_one(doc! {"id": session_data.uid}, None).await;

            let doc_opt = match result {
                Ok(doc_opt) => doc_opt,
                Err(e) => return Err(ErrorInternalServerError(e)),
            };

            let doc = match doc_opt {
                Some(doc) => doc,
                None => return Err(ErrorUnauthorized("not logged in")),
            };

            match parse_user(doc) {
                Ok(user) => Ok(user),
                Err(e) => Err(ErrorInternalServerError(e)),
            }
        })
    }
}

struct InternalSession {
    jar: CookieJar,
    session_data: Option<SessionData>,
    key: Key,
    client: Client,
}

struct InnerSession {
    client: Client,
    key: Key,
}

pub struct Session {
    inner: Rc<InnerSession>,
}

impl Session {
    pub fn new(client: Client, key: Vec<u8>) -> Self {
        Self {
            inner: Rc::new(InnerSession {
                client,
                key: Key::derive_from(&key),
            }),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Session
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>>,
    S::Future: 'static,
    S::Error: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type InitError = ();
    type Transform = SessionMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SessionMiddleware {
            service,
            inner: self.inner.clone(),
        })
    }
}

pub struct SessionMiddleware<S> {
    service: S,
    inner: Rc<InnerSession>,
}

impl<S, B> Service<ServiceRequest> for SessionMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>>,
    S::Future: 'static,
    S::Error: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let mut session_data: Option<SessionData> = None;
        let mut jar = CookieJar::new();
        if let Some(cookie) = req.cookie(COOKIE_NAME) {
            jar.add_original(cookie.clone());
            match jar.private(&self.inner.key).get(COOKIE_NAME) {
                Some(cookie) => match serde_json::from_str(cookie.value()) {
                    Ok(s) => session_data = Some(s),
                    Err(_) => jar.remove(cookie),
                },
                _ => jar.remove(cookie),
            }
        }

        let internal_session = InternalSession {
            jar,
            session_data,
            key: self.inner.key.clone(),
            client: self.inner.client.clone(),
        };
        req.extensions_mut().insert(internal_session);
        Box::pin(self.service.call(req))
    }
}

pub fn set_logged_in(req: &mut HttpRequest, mut res: HttpResponse, user: &User) -> HttpResponse {
    let mut extensions = req.extensions_mut();
    let internal_session = match extensions.get_mut::<InternalSession>() {
        Some(internal_session) => internal_session,
        None => return HttpResponse::InternalServerError().finish(),
    };

    let session_data = SessionData::new(user.id);
    let mut cookie = Cookie::new(COOKIE_NAME, serde_json::to_string(&session_data).unwrap());
    cookie.set_same_site(SameSite::Strict);
    cookie.set_http_only(true);
    cookie.set_path("/");
    #[cfg(feature = "secure")]
    cookie.set_secure(true);
    cookie.make_permanent();
    internal_session
        .jar
        .private_mut(&internal_session.key)
        .add(cookie);

    for cookie in internal_session.jar.delta() {
        let val = HeaderValue::from_str(&cookie.encoded().to_string()).unwrap();
        res.headers_mut().append(SET_COOKIE, val);
    }

    res
}

pub fn logout(req: &mut HttpRequest) -> HttpResponse {
    let mut extensions = req.extensions_mut();
    let internal_session = match extensions.get_mut::<InternalSession>() {
        Some(internal_session) => internal_session,
        None => return HttpResponse::InternalServerError().finish(),
    };

    if let Some(cookie) = internal_session.jar.get(COOKIE_NAME) {
        let cookie = cookie.clone();
        internal_session.jar.remove(cookie);
    }

    let mut res = HttpResponse::Ok().finish();
    for cookie in internal_session.jar.delta() {
        let val = HeaderValue::from_str(&cookie.encoded().to_string()).unwrap();
        res.headers_mut().append(SET_COOKIE, val);
    }
    res
}
