import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class AgentAuthDto {
  @IsUUID()
  serverId!: string;

  @IsString()
  @IsNotEmpty()
  accessKey!: string;

  @IsString()
  @IsNotEmpty()
  secret!: string;
}
