import axios from "axios";
import { serverUrl_fn } from "./appinfo";
const parseAppId = process.env.REACT_APP_APPID
  ? process.env.REACT_APP_APPID
  : "effisign";
const serverUrl = serverUrl_fn();
const parseHeaders = () => {
  const headers = {
    "Content-Type": "application/json",
    "X-Parse-Application-Id": parseAppId
  };
  const sessionToken = localStorage.getItem("accesstoken");
  if (sessionToken) {
    headers["X-Parse-Session-Token"] = sessionToken;
  }
  return headers;
};

export const SaveFileSize = async (size, imageUrl, tenantId) => {
  //checking server url and save file's size
  const tenantPtr = {
    __type: "Pointer",
    className: "partners_Tenant",
    objectId: tenantId
  };
  const _tenantPtr = JSON.stringify(tenantPtr);
  try {
    const res = await axios.get(
      `${serverUrl}/classes/partners_TenantCredits?where={"PartnersTenant":${_tenantPtr}}`,
      {
        headers: parseHeaders()
      }
    );
    const response = res.data.results;
    let data;
    // console.log("response", response);
    if (response && response.length > 0) {
      data = {
        usedStorage: response[0].usedStorage
          ? response[0].usedStorage + size
          : size
      };
      await axios.put(
        `${serverUrl}/classes/partners_TenantCredits/${response[0].objectId}`,
        data,
        {
          headers: parseHeaders()
        }
      );
    } else {
      data = { usedStorage: size, PartnersTenant: tenantPtr };
      await axios.post(`${serverUrl}/classes/partners_TenantCredits`, data, {
        headers: parseHeaders()
      });
    }
  } catch (err) {
    console.log("err in save usage", err);
  }
  saveDataFile(size, imageUrl, tenantPtr);
};

//function for save fileUrl and file size in particular client db class partners_DataFiles
const saveDataFile = async (size, imageUrl, tenantPtr) => {
  const data = {
    FileUrl: imageUrl,
    FileSize: size,
    TenantPtr: tenantPtr
  };

  // console.log("data save",file, data)
  try {
    await axios.post(`${serverUrl}/classes/partners_DataFiles`, data, {
      headers: parseHeaders()
    });
  } catch (err) {
    console.log("err in save usage ", err);
  }
};
