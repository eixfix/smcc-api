import { IsArray, IsNotEmpty, IsOptional, IsString, IsUUID } from 'class-validator';

export class AgentAuthDto {
  @IsUUID()
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
