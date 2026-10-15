import { BadRequestException, Injectable, type PipeTransform } from '@nestjs/common';
import type { ZodError, ZodType } from 'zod';

function validationMessage(error: ZodError): string {
  const flat = error.flatten();
  const parts = [
    ...flat.formErrors,
    ...Object.values(flat.fieldErrors).flatMap((messages) => messages ?? []),
  ];
  return [...new Set(parts)].join(' ') || 'Validation failed';
}

@Injectable()
export class ZodValidationPipe<T> implements PipeTransform<unknown, T> {
  constructor(private readonly schema: ZodType<T>) {}

  transform(value: unknown): T {
    const parsed = this.schema.safeParse(value ?? {});
    if (!parsed.success) {
      throw new BadRequestException({
        message: validationMessage(parsed.error),
        details: parsed.error.flatten(),
      });
    }
    return parsed.data;
  }
}
