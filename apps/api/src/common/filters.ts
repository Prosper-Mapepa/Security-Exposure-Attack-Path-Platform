import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import type { Response } from 'express';
import type { AppRequest } from './types';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('http');

  catch(exception: unknown, host: ArgumentsHost) {
    const context = host.switchToHttp();
    const response = context.getResponse<Response>();
    const request = context.getRequest<AppRequest>();
    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const payload = exception instanceof HttpException ? exception.getResponse() : null;
    const message =
      typeof payload === 'string'
        ? payload
        : payload && typeof payload === 'object' && 'message' in payload
          ? (payload as { message: unknown }).message
          : 'Internal server error';
    if (status >= 500) {
      this.logger.error(
        JSON.stringify({
          requestId: request.requestId,
          path: request.url,
          message: exception instanceof Error ? exception.message : 'unknown error',
        }),
      );
    }
    response.status(status).json({
      error: {
        code: HttpStatus[status] ?? 'ERROR',
        message,
        details:
          payload && typeof payload === 'object' && 'details' in payload
            ? (payload as { details: unknown }).details
            : undefined,
        requestId: request.requestId,
      },
    });
  }
}
