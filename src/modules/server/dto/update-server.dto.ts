import { IsBoolean, IsIP, IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateServerDto {
  @IsOptional()
  @IsString()
  @MaxLength(120)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(150)
  hostname?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @IsOptional()
  @IsString()
  @IsIP()
  allowedIp?: string;

  @IsOptional()
  @IsBoolean()
  isSuspended?: boolean;
}
