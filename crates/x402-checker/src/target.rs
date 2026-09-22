//! The server under test and the state shared by the suites.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};

use crate::http::Client;

/// The protected resource to exercise.
#[derive(Debug, Clone)]
pub struct Target {
    /// Its URL.
    pub url: Url,
    /// The method the resource expects.
    pub method: Method,
    /// Extra request headers the operator asked for (authentication, tenant, ...).
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// A request body for methods that take one.
    pub body: Option<String>,
}

/// Options that change what the suites do.
#[derive(Debug, Clone)]
pub struct Options {
    /// Allow paying on a network the tool does not know as a testnet.
    pub allow_mainnet: bool,
    /// Per-request timeout.
    pub timeout: Duration,
}

/// What every suite works with.
#[derive(Debug)]
pub struct Context {
    /// The recording HTTP client.
    pub client: Client,
    /// The resource.
    pub target: Target,
    /// Run options.
    pub options: Options,
}

impl Context {
    /// A context with a fresh client.
    pub fn new(target: Target, options: Options) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: Client::new(options.timeout)?,
            target,
            options,
        })
    }

    /// A request to the resource with the operator's headers and body. A header in `protocol` replaces any
    /// operator header of the same name: the suite owns the x402 headers of the requests it sends.
    ///
    /// # Panics
    ///
    /// Never in practice: the builder only fails on an invalid URL, which was parsed earlier, and the protocol
    /// header values are ASCII the suites produce themselves.
    pub fn resource_request(&self, protocol: &[(&str, &str)]) -> reqwest::Request {
        let mut headers = HeaderMap::new();
        for (name, value) in &self.target.headers {
            headers.append(name, value.clone());
        }
        for (name, value) in protocol {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("protocol header names are constants");
            headers.insert(
                name,
                HeaderValue::from_str(value).expect("protocol header values are ASCII"),
            );
        }
        let mut builder = self
            .client
            .request(self.target.method.clone(), self.target.url.clone())
            .headers(headers);
        if let Some(body) = &self.target.body {
            builder = builder.body(body.clone());
        }
        builder.build().expect("a request to a parsed URL builds")
    }
}
