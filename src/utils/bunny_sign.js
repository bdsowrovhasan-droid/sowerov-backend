// BunnyCDN URL Token Authentication helper
// Docs pattern: token = md5(SECURITY_KEY + path + expiry); query ?token=...&expires=<unix>
import crypto from "crypto";
export function bunnySign(urlPath, expiryUnix, securityKey){
  const hash = crypto.createHash("md5").update(securityKey + urlPath + expiryUnix).digest("hex");
  return { token: hash, expires: expiryUnix };
}
