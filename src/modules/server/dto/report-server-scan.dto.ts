import { IsEnum, IsNotEmpty, IsObject, IsOptional, IsString } from 'class-validator';
import { ServerScanStatus } from '@prisma/client';

export class ReportServerScanDto {
  @IsEnum(ServerScanStatus)
  status!: ServerScanStatus;

  @IsOptional()
  @IsString()
  failureReason?: string;

  @IsOptional()
  @IsObject()
  summary?: Record<string, unknown>;

  @IsOptional()
  @IsString()
  rawLog?: string;

  @IsOptional()
  @IsObject()
  storageMetrics?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  memoryMetrics?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  securityFindings?: Record<string, unknown>;
}
