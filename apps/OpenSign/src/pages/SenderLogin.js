import React, { useState, useEffect } from "react";
import Parse from "parse";
import axios from "axios";
import { useDispatch } from "react-redux";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import Loader from "../primitives/Loader";
import SelectLanguage from "../components/pdf/SelectLanguage";
import { showTenant } from "../redux/reducers/ShowTenant";

function SenderLogin() {
  const { session } = useParams();
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [isLoading, setIsLoading] = useState(true);
  const handleServerUrl = () => {
    localStorage.setItem("accesstoken", session);
    const returnUrl = queryParams.get("returnUrl");
    const tenantId = queryParams.get("tenantId");
    localStorage.setItem("returnUrl", returnUrl);
    localStorage.setItem("TenantId", tenantId);

    setTimeout(async () => {
      const baseUrl = localStorage.getItem("baseUrl");
      const parseAppId = localStorage.getItem("parseAppId");
      await axios.get(baseUrl + "users/me", {
        headers: {
          "X-Parse-Session-Token": session,
          "X-Parse-Application-Id": parseAppId
        }
      });
      await Parse.User.become(session).then(() => {
        window.localStorage.setItem("accesstoken", session);
      });
      Parse.Cloud.run("getUserDetails", { _SessionToken: session })
        .then(async (extUser) => {
          if (extUser) {
            // console.log("extUser", extUser, extUser?.get("IsDisabled"));
            const IsDisabled = extUser?.get("IsDisabled") || false;
            if (!IsDisabled) {
              const userRole = extUser?.get("UserRole");

              const _currentRole = userRole;
              const redirectUrl = queryParams.get("goto") || "/";
              let _role = _currentRole.replace("contracts_", "");
              localStorage.setItem("_user_role", _role);
              //const checkLanguage = extUser?.get("Language");
              // if (checkLanguage) {
              //   checkLanguage && i18n.changeLanguage(checkLanguage);
              // }

              const results = [extUser];
              const extUser_str = JSON.stringify(results);

              localStorage.setItem("Extand_Class", extUser_str);
              const extInfo = JSON.parse(JSON.stringify(extUser));
              localStorage.setItem("userEmail", extInfo.Email);
              localStorage.setItem("username", extInfo.Name);
              if (extInfo?.TenantId) {
                const tenant = {
                  Id: extInfo?.TenantId?.objectId || "",
                  Name: extInfo?.TenantId?.TenantName || ""
                };
                localStorage.setItem("TenantId", tenant?.Id);
                dispatch(showTenant(tenant?.Name));
                localStorage.setItem("TenantName", tenant?.Name);
              }
              // localStorage.setItem("PageLanding", menu.pageId);
              // localStorage.setItem("defaultmenuid", menu.menuId);
              // localStorage.setItem("pageType", menu.pageType);

              const LocalUserDetails = {
                name: results[0].get("Name"),
                email: results[0].get("Email"),
                phone: results[0]?.get("Phone") || "",
                company: results[0].get("Company")
              };
              localStorage.setItem(
                "userDetails",
                JSON.stringify(LocalUserDetails)
              );
              navigate(redirectUrl);
            }
          }
        })
        .catch((error) => {
          console.error("Error while fetching Follow", error);
        });
    }, 400);

    setIsLoading(false);
  };

  useEffect(() => {
    handleServerUrl();
  }, [handleServerUrl]);

  return (
    <div className="p-14">
      <div>
        <div className="flex flex-col justify-center items-center h-[100vh]">
          <Loader />
          <span className="text-[13px] text-[gray]">{isLoading.message}</span>
        </div>
      </div>
      <SelectLanguage />
    </div>
  );
}

export default SenderLogin;
