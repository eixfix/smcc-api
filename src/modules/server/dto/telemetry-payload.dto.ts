import { IsNumber, IsObject, IsOptional, Max, Min } from 'class-validator';

export class TelemetryPayloadDto {
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  cpuPercent?: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  memoryPercent?: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  diskPercent?: number;

  @IsOptional()
  @IsObject()
  raw?: Record<string, unknown>;
}
