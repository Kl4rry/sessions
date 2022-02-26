use std::{
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_web::{
    body::MessageBody,
    cookie::{Cookie, CookieJar, Key, SameSite},
    dev::{Payload, ServiceRequest, ServiceResponse},
    error::{ErrorInternalServerError, ErrorUnauthorized},
    http::header::{HeaderValue, SET_COOKIE},
    Error, FromRequest, HttpMessage, HttpRequest,
};
use futures_util::future::{err, ok, LocalBoxFuture, Ready};
use mongodb::{bson, bson::doc, Client};
use serde::{Deserialize, Serialize};
use serde_repr::*;
use uuid::Uuid;

pub struct Id {
    id: Uuid,
}

impl From<Id> for Uuid {
    fn from(session_id: Id) -> Self {
        session_id.id
    }
}

impl FromRequest for Id {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let extensions = req.extensions();

        let internal_session = match extensions.get::<InternalSession>() {
            Some(internal_session) => internal_session,
            None => return err(ErrorInternalServerError("unable to get indentifier")),
        };

        ok(Id {
            id: internal_session.id,
        })
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Permission {
    Admin = 0,
    Invite = 1,
    UploadClip = 2,
    Recept = 3,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: i64,
    pub permissions: Vec<Permission>,
    #[serde(skip_serializing)]
    pub password: String,
    #[serde(skip_serializing)]
    pub sessions: Vec<Uuid>,
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
        let id = internal_session.id;
        Box::pin(async move {
            let result = users
                .find_one(doc! {"sessions": id.to_hyphenated().to_string()}, None)
                .await;

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
    id: Uuid,
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
    pub fn new(client: Client, key: &[u8]) -> Self {
        Self {
            inner: Rc::new(InnerSession {
                client,
                key: Key::derive_from(key),
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
        let mut id_opt: Option<Uuid> = None;
        let mut jar = CookieJar::new();
        if let Some(cookie) = req.cookie("session") {
            jar.add_original(cookie);
            let cookie_opt = jar.private(&self.inner.key).get("session");
            if let Some(cookie) = cookie_opt {
                id_opt = Uuid::parse_str(cookie.value()).ok();
            }
        }

        let id = match id_opt {
            Some(id) => id,
            None => Uuid::new_v4(),
        };

        let internal_session = InternalSession {
            id,
            client: self.inner.client.clone(),
        };
        req.extensions_mut().insert(internal_session);

        let fut = self.service.call(req);
        let key = self.inner.key.clone();

        Box::pin(async move {
            fut.await.map(|mut res| {
                let mut cookie = Cookie::new("session", id.to_hyphenated().to_string());
                cookie.set_same_site(SameSite::Strict);
                cookie.set_http_only(true);
                cookie.set_path("/");
                #[cfg(feature = "secure")]
                cookie.set_secure(true);
                cookie.make_permanent();
                jar.private_mut(&key).add(cookie);

                for cookie in jar.delta() {
                    let val = HeaderValue::from_str(&cookie.encoded().to_string()).unwrap();
                    res.headers_mut().append(SET_COOKIE, val);
                }
                res
            })
        })
    }
}
