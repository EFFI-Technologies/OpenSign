import axios from "axios";
import Parse from "parse";

let isInstalled = false;

const getHeader = (headers, key) => {
  if (!headers) {
    return "";
  }

  return (
    headers[key] ||
    headers[key.toLowerCase()] ||
    headers[key.toUpperCase()] ||
    ""
  );
};

const setHeader = (headers, key, value) => {
  if (!value || getHeader(headers, key)) {
    return;
  }

  headers[key] = value;
};

const getSessionToken = () =>
  localStorage.getItem("accesstoken") ||
  Parse.User.current()?.getSessionToken() ||
  "";

const getParseBaseUrl = () => {
  const baseUrl = localStorage.getItem("baseUrl") || Parse.serverURL || "";

  if (!baseUrl) {
    return null;
  }

  return new URL(baseUrl, window.location.origin);
};

const isParseRequest = (url) => {
  const baseUrl = getParseBaseUrl();

  if (!baseUrl || !url) {
    return false;
  }

  const requestUrl = new URL(url, window.location.origin);
  return (
    requestUrl.origin === baseUrl.origin &&
    requestUrl.pathname.startsWith(baseUrl.pathname)
  );
};

export const buildParseAuthHeaders = ({
  jwtToken,
  sessionToken = getSessionToken()
} = {}) => {
  const headers = {
    "X-Parse-Application-Id":
      localStorage.getItem("parseAppId") ||
      process.env.REACT_APP_APPID ||
      "effisign"
  };

  if (jwtToken) {
    headers.jwttoken = jwtToken;
    return headers;
  }

  if (sessionToken) {
    headers.sessiontoken = sessionToken;
    headers["X-Parse-Session-Token"] = sessionToken;
  }

  return headers;
};

export const installAxiosParseAuth = () => {
  if (isInstalled) {
    return;
  }

  axios.interceptors.request.use((config) => {
    if (!isParseRequest(config?.url)) {
      return config;
    }

    config.headers = config.headers || {};

    const jwtToken = getHeader(config.headers, "jwttoken");
    const headerSessionToken =
      getHeader(config.headers, "X-Parse-Session-Token") ||
      getHeader(config.headers, "sessiontoken") ||
      getHeader(config.headers, "sessionToken");
    const authHeaders = buildParseAuthHeaders({
      jwtToken,
      sessionToken: headerSessionToken || getSessionToken()
    });

    Object.entries(authHeaders).forEach(([key, value]) => {
      setHeader(config.headers, key, value);
    });

    return config;
  });

  isInstalled = true;
};
