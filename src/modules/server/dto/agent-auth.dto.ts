import { IsArray, IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';

export class AgentAuthDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(36)
  serverId!: string;

  @IsString()
  @IsNotEmpty()
  accessKey!: string;

  @IsString()
  @IsNotEmpty()
  secret!: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  capabilities?: string[];
}
