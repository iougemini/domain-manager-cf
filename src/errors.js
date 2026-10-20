// 统一错误处理模块 - 错误码、错误类与标准响应工厂

export const ERROR_CODES = {
  AUTH_FAILED: 'AUTH_FAILED',
  AUTH_EXPIRED: 'AUTH_EXPIRED',
  RATE_LIMITED: 'RATE_LIMITED',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  CONFIG_ERROR: 'CONFIG_ERROR',
  API_ERROR: 'API_ERROR'
};

export class ApiError extends Error {
  constructor(code, message, statusCode = 400, details = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class ValidationError extends Error {
  constructor(message, field = null) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
    this.userMessage = message;
  }
}

export function createErrorResponse(error, statusCode = 400) {
  const isApiError = error instanceof ApiError;
  const isValidationError = error instanceof ValidationError;

  const response = {
    success: false,
    error: {
      code: isApiError ? error.code : (isValidationError ? ERROR_CODES.VALIDATION_ERROR : ERROR_CODES.INTERNAL_ERROR),
      message: error.message || 'An error occurred'
    }
  };

  if (isApiError && error.details) {
    response.error.details = error.details;
  }

  if (isValidationError && error.field) {
    response.error.field = error.field;
  }

  return new Response(JSON.stringify(response), {
    status: isApiError ? error.statusCode : statusCode,
    headers: { 'Content-Type': 'application/json' }
  });
}

export function createSuccessResponse(data, statusCode = 200) {
  return new Response(JSON.stringify({
    success: true,
    data: data
  }), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' }
  });
}