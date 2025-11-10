import { IsIP, IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';

export class CreateServerDto {
  @IsString()
  @IsNotEmpty()
  organizationId!: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  name!: string;

  @IsOptional()
  @IsString()
  @MaxLength(150)
  hostname?: string;

  @IsString()
  @IsNotEmpty()
  @IsIP()
  allowedIp!: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}
