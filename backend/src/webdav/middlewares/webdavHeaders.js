import { WEBDAV_BASE_PATH } from "../auth/config/WebDAVConfig.js";
import { getStandardWebDAVHeaders } from "../utils/headerUtils.js";

const isWebDAVPath = (path, basePath) => path === basePath || path.startsWith(`${basePath}/`);

export const webdavHeaders = (options = {}) => {
  const basePath = options.basePath || WEBDAV_BASE_PATH;

  return async (c, next) => {
    const shouldApply = isWebDAVPath(c.req.path, basePath);

    try {
      await next();
    } finally {
      if (!shouldApply) {
        return;
      }

      // 从请求中提取Origin，用于动态CORS处理
      const requestOrigin = c.req.header("Origin") || null;
      const headers = getStandardWebDAVHeaders({ ...options, requestOrigin });
      const responseHeaders = c.res.headers;

      for (const [key, value] of Object.entries(headers)) {
        // CORS头始终覆盖，确保动态Origin和Credentials正确
        if (key.startsWith("Access-Control-") || !responseHeaders.has(key)) {
          responseHeaders.set(key, value);
        }
      }
    }
  };
};
