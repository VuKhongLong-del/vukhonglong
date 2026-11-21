const PROJECT_ID = "vukhonglong-9cfcb";
const ALLOWED_ORIGIN = "https://vukhonglong.github.io";

let cachedAccessToken = null;
let accessTokenExpiry = 0;
let cachedJwks = null;
let jwksExpiry = 0;

function b64url(data) {
  const bytes = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data;
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function decodePart(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return JSON.parse(atob(padded));
}

function pemToBytes(pem) {
  const clean = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const binary = atob(clean);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function verifyFirebaseToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Token đăng nhập không hợp lệ.");

  const header = decodePart(parts[0]);
  const claims = decodePart(parts[1]);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Chữ ký đăng nhập không hợp lệ.");
  }

  if (!cachedJwks || Date.now() > jwksExpiry) {
    const response = await fetch(
      "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
    );
    if (!response.ok) throw new Error("Không xác minh được tài khoản.");
    cachedJwks = await response.json();
    jwksExpiry = Date.now() + 3600000;
  }

  const jwk = cachedJwks.keys.find(key => key.kid === header.kid);
  if (!jwk) throw new Error("Khóa xác minh đã hết hạn.");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signaturePart = parts[2].replace(/-/g, "+").replace(/_/g, "/");
  const paddedSignature = signaturePart + "=".repeat((4 - signaturePart.length % 4) % 4);

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    Uint8Array.from(atob(paddedSignature), c => c.charCodeAt(0)),
    new TextEncoder().encode(parts[0] + "." + parts[1])
  );

  const now = Math.floor(Date.now() / 1000);

  if (!valid ||
      claims.aud !== PROJECT_ID ||
      claims.iss !== "https://securetoken.google.com/" + PROJECT_ID ||
      !claims.sub ||
      claims.exp <= now ||
      claims.iat > now + 60) {
    throw new Error("Phiên đăng nhập không hợp lệ hoặc đã hết hạn.");
  }

  return claims;
}

async function getGoogleAccessToken(env) {
  if (cachedAccessToken && Date.now() < accessTokenExpiry - 60000) {
    return cachedAccessToken;
  }

  const service = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);

  const unsigned = b64url(JSON.stringify({
    alg: "RS256",
    typ: "JWT"
  })) + "." + b64url(JSON.stringify({
    iss: service.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToBytes(service.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(unsigned)
  );

  const assertion = unsigned + "." + b64url(new Uint8Array(signature));

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error("Không kết nối được Firebase: " +
      (result.error_description || result.error));
  }

  cachedAccessToken = result.access_token;
  accessTokenExpiry = Date.now() + result.expires_in * 1000;
  return cachedAccessToken;
}

function field(value) {
  if (value == null) return null;
  if (value.stringValue !== undefined) return value.stringValue;
  if (value.integerValue !== undefined) return Number(value.integerValue);
  if (value.doubleValue !== undefined) return Number(value.doubleValue);
  if (value.booleanValue !== undefined) return value.booleanValue;
  if (value.mapValue) return decodeFields(value.mapValue.fields || {});
  if (value.arrayValue) return (value.arrayValue.values || []).map(field);
  return null;
}

function decodeFields(fields) {
  const result = {};
  for (const [key, value] of Object.entries(fields || {})) {
    result[key] = field(value);
  }
  return result;
}

function str(value) {
  return { stringValue: String(value ?? "") };
}

function integer(value) {
  return { integerValue: String(value) };
}

function timestamp(value = new Date()) {
  return { timestampValue: value.toISOString() };
}

function mapValue(object) {
  const fields = {};
  for (const [key, value] of Object.entries(object)) {
    if (typeof value === "string") fields[key] = str(value);
    else if (typeof value === "number") fields[key] = integer(value);
    else if (typeof value === "boolean") {
      fields[key] = { booleanValue: value };
    } else if (Array.isArray(value)) {
      fields[key] = {
        arrayValue: {
          values: value.map(item => ({ mapValue: mapValue(item) }))
        }
      };
    }
  }
  return { mapValue: { fields } };
}

async function firestoreRequest(path, token, body) {
  const response = await fetch(
    "https://firestore.googleapis.com/v1/projects/" +
    PROJECT_ID + "/databases/(default)/documents" + path,
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    }
  );

  const text = await response.text();
  let data = null;

  try {
    if (path.includes(":batchGet")) {
      data = text
        .split(/\r?\n/)
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
    } else {
      data = text ? JSON.parse(text) : {};
    }
  } catch (error) {
    throw new Error(
      "Không đọc được dữ liệu Firestore: " + text.slice(0, 300)
    );
  }

  if (!response.ok) {
    const message = Array.isArray(data)
      ? data[0]?.error?.message
      : data?.error?.message;

    throw new Error(message || "Lỗi thao tác dữ liệu Firebase.");
  }

  return data;
}

function getDocumentFields(doc) {
  return doc?.fields ? decodeFields(doc.fields) : null;
}

async function buyLv0(env, uid, claims, input) {
  const quantity = Number(input.quantity);
  const orderId = String(input.orderId || "");

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 30) {
    throw new Error("Số lượng mỗi đơn chỉ được từ 1 đến 30 ACC.");
  }

  if (!/^VKL-[A-F0-9]{32}$/.test(orderId)) {
    throw new Error("Mã đơn hàng không hợp lệ.");
  }

  const total = quantity * 50;
  const token = await getGoogleAccessToken(env);
  const root = "projects/" + PROJECT_ID +
    "/databases/(default)/documents";

  const txResult = await firestoreRequest(":beginTransaction", token, {
    options: { readWrite: {} }
  });
  const tx = txResult.transaction;

  try {
    const names = [
      root + "/wallets/" + uid,
      root + "/orders/" + orderId
    ];

    const docs = await firestoreRequest(":batchGet", token, {
      documents: names,
      transaction: tx
    });

    const walletDoc = docs.find(d => d.found?.name === names[0])?.found;
    const orderDoc = docs.find(d => d.found?.name === names[1])?.found;

    if (orderDoc) {
      const oldOrder = getDocumentFields(orderDoc);
      if (oldOrder.userId !== uid || !oldOrder.deliveredAccounts) {
        throw new Error("Mã đơn này đã được sử dụng.");
      }
      // Close the read-only transaction before returning an idempotent result.
      await firestoreRequest(":rollback", token, { transaction: tx });
      return {
        orderId,
        deliveredAccounts: oldOrder.deliveredAccounts,
        balance: null,
        repeated: true
      };
    }

    if (!walletDoc) throw new Error("Không tìm thấy ví Xu.");

    const wallet = getDocumentFields(walletDoc);
    const oldBalance = Number(wallet.coins || 0);

    if (!Number.isSafeInteger(oldBalance) || oldBalance < total) {
      throw new Error("Số dư không đủ. Bạn cần " + total + " Xu.");
    }

    const stock = await firestoreRequest(":runQuery", token, {
      structuredQuery: {
        from: [{ collectionId: "accInventory" }],
        where: {
          fieldFilter: {
            field: { fieldPath: "level" },
            op: "EQUAL",
            value: str("LV0")
          }
        },
        limit: 1000
      },
      transaction: tx
    });

    const available = stock
      .filter(item => item.document)
      .map(item => item.document)
      .filter(doc => {
        const data = getDocumentFields(doc);
        return data &&
          data.level === "LV0" &&
          data.account &&
          data.password &&
          data.status !== "sold" &&
          data.sold !== true;
      });

    if (available.length < quantity) {
      throw new Error(
        "Kho ACC LV0 không đủ số lượng. Hiện tìm thấy " +
        available.length + " ACC có thể bán."
      );
    }

    const selected = available.slice(0, quantity);
    const deliveredAccounts = selected.map(doc => {
      const data = getDocumentFields(doc);
      return { account: data.account, password: data.password };
    });

    const newBalance = oldBalance - total;
    const username = String(claims.email || "").split("@")[0];

    const writes = [{
      update: {
        name: names[0],
        fields: {
          coins: integer(newBalance),
          lastOrderId: str(orderId),
          updatedAt: timestamp()
        }
      },
      updateMask: {
        fieldPaths: ["coins", "lastOrderId", "updatedAt"]
      }
    }];

    for (let i = 0; i < selected.length; i++) {
      writes.push({
        update: {
          name: selected[i].name,
          fields: {
            status: str("sold"),
            sold: { booleanValue: true },
            soldTo: str(uid),
            orderId: str(orderId),
            soldAt: timestamp()
          }
        },
        updateMask: {
          fieldPaths: ["status", "sold", "soldTo", "orderId", "soldAt"]
        }
      });
    }

    writes.push(
      {
        update: {
          name: root + "/orders/" + orderId,
          fields: {
            userId: str(uid),
            username: str(username),
            service: str("ACC CLONE LV0"),
            count: integer(quantity),
            quantity: integer(quantity),
            total: integer(total),
            codes: str(""),
            date: str(new Date().toLocaleString("vi-VN")),
            label: str("Tổng số acc clone"),
            deliveredAccounts: {
              arrayValue: {
                values: deliveredAccounts.map(item => ({
                  mapValue: mapValue(item)
                }))
              }
            },
            deliveryStatus: str("Đã giao tài khoản"),
            createdAt: timestamp()
          }
        }
      },
      {
        update: {
          name: root + "/orderTracking/" + orderId,
          fields: {
            userId: str(uid),
            service: str("ACC CLONE LV0"),
            status: str("Đã giao tài khoản"),
            progress: integer(100),
            eta: str("Đã giao tự động"),
            note: str("Tài khoản đã được giao trong đơn hàng."),
            updatedAt: timestamp()
          }
        }
      },
      {
        update: {
          name: root + "/coinTransactions/" + orderId,
          fields: {
            uid: str(uid),
            userId: str(wallet.userId || ""),
            type: str("subtract"),
            amount: integer(total),
            balanceAfter: integer(newBalance),
            note: str("Thanh toán đơn hàng " + orderId),
            createdAt: timestamp()
          }
        }
      }
    );

    await firestoreRequest(":commit", token, {
      writes,
      transaction: tx
    });

    return {
      orderId,
      deliveredAccounts,
      balance: newBalance,
      repeated: false
    };
  } catch (error) {
    try {
      await firestoreRequest(":rollback", token, {
        transaction: tx
      });
    } catch (_) {}
    throw error;
  }
}

function response(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Vary": "Origin"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check: mở URL Worker trực tiếp (GET) luôn trả trạng thái,
    // không cần thêm ?test=1 và không cần đăng nhập.
    if (request.method === "GET") {
      return new Response(
        JSON.stringify({
          success: true,
          message: "CONCU WORKER ONLINE",
          project: PROJECT_ID
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store"
          }
        }
      );
    }

    const origin = request.headers.get("Origin") || "";

    if (origin !== ALLOWED_ORIGIN) {
      return new Response("Origin not allowed", { status: 403 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    if (request.method !== "POST") {
      return response(
        { error: "Method not allowed" },
        405,
        origin
      );
    }

    let stage = "request";
    try {
      stage = "authorization";
      const authorization = request.headers.get("Authorization") || "";
      if (!authorization.startsWith("Bearer ")) {
        throw new Error("Vui lòng đăng nhập lại.");
      }

      stage = "firebase-token";
      const claims = await verifyFirebaseToken(
        authorization.slice(7)
      );
      stage = "request-body";
      const input = await request.json();

      if (input.service !== "cloneLv0") {
        throw new Error("Worker chỉ xử lý đơn ACC CLONE LV0.");
      }

      stage = "firestore-purchase";
      const result = await buyLv0(env, claims.sub, claims, input);

      return response({
        success: true,
        ...result
      }, 200, origin);

    } catch (error) {
      // Return readable CORS-enabled diagnostics instead of a browser-level
      // "Load failed"; never include tokens, private keys, or account data.
      const message = error && error.message
        ? error.message
        : "Đã xảy ra lỗi không xác định.";
      const clientError = /Token|đăng nhập|Phiên|Mã đơn|Số lượng|Số dư|Kho ACC|Worker chỉ|Origin/i.test(message);
      return response({
        success: false,
        stage,
        error: message
      }, clientError ? 400 : 500, origin);
    }
  }
};