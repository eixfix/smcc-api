import { IsNotEmpty, IsObject, IsOptional, IsString, MaxLength } from 'class-validator';

export class QueueServerScanDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  playbook!: string;

  @IsOptional()
  @IsObject()
  parameters?: Record<string, unknown>;
}
