import { IsString, MaxLength } from 'class-validator';

export class GoogleAuthDto {
  @IsString()
  @MaxLength(8192)
  idToken!: string;
}
