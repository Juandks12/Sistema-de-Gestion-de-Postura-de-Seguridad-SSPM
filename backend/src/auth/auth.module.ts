import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtSignOptions } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AccountTokensService } from './account-tokens.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { LoginProtectionService } from './login-protection.service';
import { MfaService } from './mfa.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { OrganizationsModule } from '../organizations/organizations.module';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: (config.get<string>('JWT_EXPIRES_IN') ?? '8h') as JwtSignOptions['expiresIn'],
        },
      }),
    }),
    OrganizationsModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, LoginProtectionService, AccountTokensService, MfaService],
  exports: [AuthService, MfaService, AccountTokensService],
})
export class AuthModule {}
