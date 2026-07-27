/**
 * WebDAV工具函数
 */

import { stripPrefix } from "../auth/config/WebDAVConfig.js";
import { AppError, ValidationError } from "../../http/errors.js";

/**
 * 统一路径处理函数
 * @param {string} rawPath - 原始路径
 * @param {boolean} throwOnError - 是否在错误时抛出异常
 * @returns {string} 处理后的路径
 */
export function processWebDAVPath(rawPath, throwOnError = false) {
  try {
    // URL解码
    const decodedPath = decodeURIComponent(rawPath);

    // 安全检查1：路径遍历防护
    if (decodedPath.includes("..")) {
      const message = `WebDAV安全警告: 检测到路径遍历攻击尝试: ${decodedPath}`;
      console.warn(message);
      if (throwOnError) {
        throw new ValidationError("Path traversal detected");
      }
      return null;
    }

    // 安全检查2：空字节注入防护
    if (decodedPath.includes("\0")) {
      const message = `WebDAV安全警告: 检测到空字节注入尝试: ${decodedPath}`;
      console.warn(message);
      if (throwOnError) {
        throw new ValidationError("Invalid path characters");
      }
      return null;
    }

    // 使用统一的stripPrefix函数处理WebDAV路径前缀
    let processedPath = stripPrefix(decodedPath);

    // 规范化路径，移除多余的斜杠
    processedPath = processedPath.replace(/\/+/g, "/");

    // 确保路径以斜杠开始
    if (!processedPath.startsWith("/")) {
      processedPath = "/" + processedPath;
    }

    return processedPath;
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    const message = `WebDAV路径解码失败: ${error.message}`;
    console.warn(message);
    if (throwOnError) {
      throw new ValidationError("Invalid path encoding");
    }
    return null;
  }
}

/**
 * 解析目标路径
 * WebDAV特有功能：处理WebDAV的Destination头
 * @param {string} destination - 目标路径头
 * @returns {string|null} 规范化的目标路径或null（如果无效）
 */
export function parseDestinationPath(destination) {
  if (!destination) {
    return null;
  }

  let destPath;
  try {
    // 尝试从完整URL中提取路径
    const url = new URL(destination);
    destPath = url.pathname;
  } catch (error) {
    // 如果不是完整URL，直接使用值作为路径
    destPath = destination;
  }

  // 使用统一的路径处理函数
  return processWebDAVPath(destPath, false);
}

/**
 * 剥离 API Key 用户名前缀
 * WebDAV 路径格式为 /{username}/mount/...，而挂载点路径是 /mount/...，
 * 剥离后可与 MountResolver/findMountPointByPath 正确匹配。
 * @param {string} path - 原始请求路径（已剥离 /dav 前缀）
 * @param {Object} userIdOrInfo - 用户ID或API密钥信息对象
 * @param {string} userType - 用户类型
 * @returns {string} 剥离用户名前缀后的文件系统路径
 */
export function stripUsernamePrefix(path, userIdOrInfo, userType) {
  if (userType === "apiKey" && typeof userIdOrInfo === "object" && (userIdOrInfo?.key || userIdOrInfo?.name)) {
    const keyId = userIdOrInfo.key || userIdOrInfo.name;
    const prefix = "/" + keyId;
    if (path === prefix || path === prefix + "/") {
      return "/";
    }
    if (path.startsWith(prefix + "/")) {
      return path.substring(prefix.length) || "/";
    }
  }
  return path;
}
