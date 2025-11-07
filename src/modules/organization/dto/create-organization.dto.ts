import { Type } from 'class-transformer';
import {
  IsEmail,
  IsString,
  Length,
  Matches,
  MinLength,
  ValidateNested
} from 'class-validator';

export class CreateOrganizationOwnerDto {
  @IsString()
  @Length(3, 60)
  name!: string;

  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  password!: string;
}

export class CreateOrganizationDto {
  @IsString()
  @Length(3, 60)
  name!: string;

  @IsString()
  @Matches(/^[a-z0-9-]+$/, {
    message: 'Slug can only include lowercase letters, numbers, and hyphens.'
  })
  slug!: string;

  @ValidateNested()
  @Type(() => CreateOrganizationOwnerDto)
  owner!: CreateOrganizationOwnerDto;
}
