import { Type } from 'class-transformer';
import {
  IsArray,
  IsEnum,
  IsIn,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  Matches,
  Min,
  ValidateNested
} from 'class-validator';
import { TaskMode } from '@prisma/client';

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

export class HttpHeaderDto {
  @IsNotEmpty()
  @IsString()
  @Matches(/^[A-Za-z0-9-]+$/, {
    message: 'Header names may only contain letters, numbers, and hyphens.'
  })
  key!: string;

  @IsString()
  @Matches(/^[^\r\n]*$/, { message: 'Header values cannot include line breaks.' })
  value!: string;
}

export class CreateTaskDto {
  @IsString()
  label!: string;

  @IsUrl({ require_tld: false, require_protocol: true, protocols: ['http', 'https'] })
  targetUrl!: string;

  @IsEnum(TaskMode)
  mode!: TaskMode;

  @IsOptional()
  @IsString()
  scheduleAt?: string;

  @IsOptional()
  @IsString()
  @IsIn(ALLOWED_METHODS, { message: `method must be one of: ${ALLOWED_METHODS.join(', ')}` })
  method?: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => HttpHeaderDto)
  headers?: HttpHeaderDto[];

  @IsOptional()
  @IsString()
  payload?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  customVus?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  durationSeconds?: number;
}
