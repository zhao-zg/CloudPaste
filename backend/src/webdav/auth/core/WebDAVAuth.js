/**
 * WebDAV认证核心
 */

import { MountManager } from "../../../storage/managers/MountManager.js";
import { UserType } from "../../../constants/index.js";
import { processWebDAVPath } from "../../utils/webdavUtils.js";
import { getAccessibleMountsForUser } from "../../../security/helpers/access.js";
import { isVirtualPath } from "../../../storage/fs/utils/VirtualDirectory.js";

/**
 * WebDAVAuth 只负责协议层兼容（Basic Challenge + 路径验权），
 * 具体的读/写授权交由 webdavRoutes 中的策略完成。
 */

/**
 * 认证结果类型枚举
 */
export const AuthResultType = {
  SUCCESS: "success",
  CHALLENGE: "challenge",
  FORBIDDEN: "forbidden",
  UNAUTHORIZED: "unauthorized",
  ERROR: "error",
};

/**
 * WebDAV认证核心类
 */
export class WebDAVAuth {
  constructor(db) {
    this.db = db;
  }

  /**
   * 验证WebDAV路径权限
   * 检查API密钥用户是否有权限访问指定路径
   * @param {Object} keyInfo - API密钥信息
   * @param {string} path - 请求路径
   * @param {string} method - HTTP方法
   * @param {Object} c - Hono上下文
   * @returns {Promise<boolean>} 是否有权限
   */
  async validateWebDAVPathPermission(keyInfo, path, method, c) {
    try {
      const basicPath = keyInfo.basicPath || "/";

      // 剥离 WebDAV 路径中的用户名前缀：
      // WebDAV 路径格式为 /{username}/mount/... ，而 basicPath 是挂载点路径（不含用户名前缀），
      // 例如 path=/zqs/2区使用/ → effectivePath=/2区使用/ ，与 basicPath=/2区使用/ 可直接前缀匹配。
      const effectivePath = this._stripUsernamePrefix(path, keyInfo.name);

      // 0. 用户根目录始终允许导航（PROPFIND 需要列出挂载点）
      if (effectivePath === "/" || effectivePath === "//") {
        return true;
      }

      // 1. 虚拟路径优先检查（根目录 / 以及不直接落在具体挂载点上的中间目录）
      //    虚拟路径是导航中间目录，只要用户已认证就允许访问，
      //    实际的数据操作（GET/PUT/DELETE）在挂载点解析阶段会失败。
      const repositoryFactory = c.get("repos");
      const accessibleMounts = await getAccessibleMountsForUser(this.db, keyInfo, "apiKey", repositoryFactory);
      if (isVirtualPath(effectivePath, accessibleMounts)) {
        return true;
      }

      // 2. 基础路径权限检查（使用剥离用户名前缀后的路径）
      if (!this.checkBasicPathPermission(basicPath, effectivePath)) {
        return false;
      }

      // 3. 实际存储路径：使用剥离前缀后的 effectivePath 进行挂载点解析
      const { getEncryptionSecret } = await import("../../../utils/environmentUtils.js");
      const mountManager = new MountManager(this.db, getEncryptionSecret(c), repositoryFactory, { env: c.env });

      try {
        await mountManager.getDriverByPath(effectivePath, keyInfo, "apiKey");
        return true;
      } catch (mountError) {
        return false;
      }
    } catch (error) {
      console.error("WebDAV路径权限检查失败:", error);
      return false;
    }
  }

  /**
   * 剥离 WebDAV 路径中的用户名前缀
   * WebDAV 路径格式为 /{username}/mount/... ，而 basicPath 是挂载点路径（不含用户名前缀），
   * 剥离后可与 basicPath 直接做前缀匹配。
   * @param {string} path - 原始请求路径
   * @param {string} keyName - API 密钥名称（即用户名）
   * @returns {string} 剥离用户名前缀后的路径
   */
  _stripUsernamePrefix(path, keyName) {
    if (!keyName) return path;
    const prefix = "/" + keyName;
    if (path === prefix || path === prefix + "/") {
      return "/"; // 用户根目录
    }
    if (path.startsWith(prefix + "/")) {
      return path.substring(prefix.length); // /mount_path/...
    }
    return path; // 不含预期前缀，原样返回
  }

  /**
   * 检查基础路径权限
   * @param {string} basicPath - 用户的基础路径
   * @param {string} requestPath - 请求的路径
   * @returns {boolean} 是否有权限
   */
  checkBasicPathPermission(basicPath, requestPath) {
    if (!basicPath || basicPath === "/") {
      return true; // 根路径权限
    }

    // 规范化路径
    const normalizedBasicPath = basicPath.endsWith("/") ? basicPath : basicPath + "/";
    const normalizedRequestPath = requestPath.startsWith("/") ? requestPath : "/" + requestPath;

    // 情况1：请求路径以基础路径开头（原有逻辑）
    // 例如 basicPath=/zqs, requestPath=/zqs/2区使用/ → 匹配
    if (normalizedRequestPath.startsWith(normalizedBasicPath) || normalizedRequestPath === basicPath) {
      return true;
    }

    // 情况2：基础路径是请求路径的尾部（后缀匹配）
    // 例如 basicPath=/2区使用, requestPath=/zqs/2区使用/ → 匹配
    // 这处理了管理面板 UI 中 basicPath 只能选择挂载点路径，
    // 而挂载点路径不包含用户子路径前缀的场景
    const normalizedBasicPathNoSlash = normalizedBasicPath.replace(/\/+$/, "");
    if (normalizedRequestPath.endsWith(normalizedBasicPathNoSlash + "/") ||
        normalizedRequestPath === normalizedBasicPathNoSlash ||
        normalizedRequestPath.endsWith(normalizedBasicPathNoSlash)) {
      return true;
    }

    return false;
  }

  /**
   * 生成认证挑战 - 符合RFC 4918 WebDAV标准
   * 发送Basic认证挑战
   * @returns {Object} 认证挑战结果
   */
  generateAuthChallenge() {
    return {
      type: AuthResultType.CHALLENGE,
      message: "需要认证",
      headers: {
        "WWW-Authenticate": 'Basic realm="WebDAV"',
      },
    };
  }

  /**
   * 创建中间件
   * @returns {Function} 中间件函数
   */
  createMiddleware() {
    return async (c, next) => {
      try {
        // 获取并处理请求路径
        const url = new URL(c.req.url);
        const rawPath = url.pathname;
        let requestPath = this.processPath(rawPath);
        c.set("webdavPath", requestPath);

        // OPTIONS 方法特殊处理 - 允许未认证访问进行能力发现
        if (c.req.method === "OPTIONS") {
          // 直接跳过认证，不设置用户类型（保持undefined状态）
          return await next();
        }

        // 统一认证处理
        const authResult = await this.performUnifiedAuth(c, requestPath);

        if (authResult.type === AuthResultType.SUCCESS) {
          c.set("userType", authResult.userType);
          c.set("userId", authResult.userId);
          return await next();
        } else if (authResult.type === AuthResultType.CHALLENGE) {
          // 返回认证挑战
          return new Response("Unauthorized", {
            status: 401,
            headers: authResult.headers,
          });
        } else {
          // 认证失败
          return new Response(authResult.message, {
            status: authResult.type === AuthResultType.FORBIDDEN ? 403 : 401,
          });
        }
      } catch (error) {
        console.error("WebDAV中间件错误:", error);
        return new Response("Internal Server Error", { status: 500 });
      }
    };
  }

  /**
   * 统一路径处理 - 使用统一的路径处理函数
   * @param {string} rawPath - 原始路径
   * @returns {string} 处理后的路径
   */
  processPath(rawPath) {
    const processedPath = processWebDAVPath(rawPath, false);
    return processedPath || rawPath; // 如果处理失败，返回原始路径
  }

  /**
   * 统一认证处理
   * @param {Object} c - Hono上下文
   * @param {string} requestPath - 请求路径
   * @returns {Promise<Object>} 认证结果
   */
  async performUnifiedAuth(c, requestPath) {
    try {
      const principal = c.get("principal");
      if (!principal || principal.type === "anonymous") {
        return this.generateAuthChallenge();
      }

      const userType = principal.isAdmin ? UserType.ADMIN : principal.type;
      if (userType !== UserType.ADMIN && userType !== UserType.API_KEY) {
        return {
          type: AuthResultType.FORBIDDEN,
          message: "不支持的身份类型",
        };
      }

      let apiKeyInfo = null;
      if (userType === UserType.API_KEY) {
        apiKeyInfo = principal.attributes?.keyInfo ?? null;
        if (!apiKeyInfo) {
          return {
            type: AuthResultType.ERROR,
            message: "API密钥信息缺失",
          };
        }

        const hasPathPermission = await this.validateWebDAVPathPermission(apiKeyInfo, requestPath, c.req.method, c);
        if (!hasPathPermission) {
          return {
            type: AuthResultType.FORBIDDEN,
            message: "路径权限不足",
          };
        }
      }

      return {
        type: AuthResultType.SUCCESS,
        userType,
        userId: userType === UserType.ADMIN ? principal.id : apiKeyInfo,
      };
    } catch (error) {
      console.error("WebDAV统一认证错误:", error);
      return {
        type: AuthResultType.ERROR,
        message: "认证失败",
      };
    }
  }
}

/**
 * 创建WebDAV认证实例
 * @param {D1Database} db - 数据库实例
 * @returns {WebDAVAuth} 认证实例
 */
export function createWebDAVAuth(db) {
  return new WebDAVAuth(db);
}
