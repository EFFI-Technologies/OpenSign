import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
const Footer = () => {
  const { t } = useTranslation();
  const [showButton, setShowButton] = useState(false);

  const handleScroll = () => {
    if (window.pageYOffset >= 50) {
      setShowButton(true);
    } else {
      setShowButton(false);
    }
  };

  const scrollToTop = () => {
    window.scrollTo(0, 0);
    setShowButton(false);
  };

  useEffect(() => {
    window.addEventListener("scroll", handleScroll);

    return () => {
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  return (
    <>
      <footer className="op-footer op-footer-center py-3 bg-base-300 text-base-content text-center text-[13px]">
        <aside>
          <p>
            &copy; {new Date().getFullYear()} EffiSign{" · "}
            <a
              href="https://github.com/EFFI-Technologies/OpenSign"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:underline"
            >
              {t("all-right")}
            </a>
          </p>
        </aside>
      </footer>
      <button
        className={`${
          showButton ? "block" : "hidden"
        } fixed bottom-4 right-4 px-3 p-2 text-xl op-bg-secondary text-white rounded focus:outline-none`}
        onClick={scrollToTop}
      >
        <i className="fa-light fa-angle-up"></i>
      </button>
    </>
  );
};

export default Footer;
