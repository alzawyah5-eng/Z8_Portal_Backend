import { IsEmail, IsString, Length, MaxLength, MinLength, Matches } from 'class-validator';

export class PasswordCredentialsDto {
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @IsString()
  @Length(8, 128)
  password!: string;
}

export class PasswordResetRequestDto {
  @IsEmail()
  @MaxLength(254)
  email!: string;
}

export class EmailVerificationDto extends PasswordResetRequestDto {
  @IsString()
  @Matches(/^\d{6}$/)
  code!: string;
}

export class PasswordResetConfirmDto extends PasswordResetRequestDto {
  @IsString()
  @MinLength(40)
  @MaxLength(128)
  token!: string;

  @IsString()
  @Length(8, 128)
  password!: string;
}

export class PasswordMigrationDto {
  @IsString()
  @Length(8, 128)
  password!: string;
}
