import React, { useEffect, useRef } from "react";

const turnstileSiteKey = process.env.REACT_APP_CAPTCHA_TURNSTILE_SITE_KEY || "";
const turnstileScriptId = "turnstile-script";
const turnstileScriptSrc =
  "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

let turnstileScriptPromise;

export const isCaptchaEnabled = Boolean(turnstileSiteKey);

function loadTurnstileScript() {
  if (window.turnstile) {
    return Promise.resolve();
  }

  if (turnstileScriptPromise) {
    return turnstileScriptPromise;
  }

  turnstileScriptPromise = new Promise((resolve, reject) => {
    const existingScript = document.getElementById(turnstileScriptId);
    if (existingScript) {
      if (existingScript.dataset.loaded === "true") {
        resolve();
        return;
      }
      existingScript.addEventListener("load", resolve, { once: true });
      existingScript.addEventListener("error", reject, { once: true });
      return;
    }

    const script = document.createElement("script");
    script.id = turnstileScriptId;
    script.src = turnstileScriptSrc;
    script.async = true;
    script.defer = true;
    script.onload = () => {
      script.dataset.loaded = "true";
      resolve();
    };
    script.onerror = reject;
    document.head.appendChild(script);
  });

  return turnstileScriptPromise;
}

function Captcha({ onVerify, resetKey }) {
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);
  const onVerifyRef = useRef(onVerify);

  useEffect(() => {
    onVerifyRef.current = onVerify;
  }, [onVerify]);

  useEffect(() => {
    let mounted = true;

    if (!turnstileSiteKey) {
      return undefined;
    }

    loadTurnstileScript()
      .then(() => {
        if (!mounted || !containerRef.current || widgetIdRef.current) {
          return;
        }

        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: turnstileSiteKey,
          callback: (token) => onVerifyRef.current(token),
          "expired-callback": () => onVerifyRef.current(""),
          "error-callback": () => onVerifyRef.current("")
        });
      })
      .catch(() => onVerifyRef.current(""));

    return () => {
      mounted = false;
      if (widgetIdRef.current !== null && window.turnstile?.remove) {
        window.turnstile.remove(widgetIdRef.current);
        widgetIdRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (widgetIdRef.current !== null && window.turnstile?.reset) {
      window.turnstile.reset(widgetIdRef.current);
      onVerifyRef.current("");
    }
  }, [resetKey]);

  if (!turnstileSiteKey) {
    return null;
  }

  return (
    <div className="mt-3 min-h-[65px]">
      <div ref={containerRef} />
    </div>
  );
}

export default Captcha;
