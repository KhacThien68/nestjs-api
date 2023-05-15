import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // save the password
    const hash = await argon.hash(dto.password);

    // save the new user to the database
    try {
      const user = await this.prisma.user.create({
        data: {
          hash: hash,
          email: dto.email,
        },
      });

      // return the saved user
      delete user.hash;
      return user;
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('this email should be unique');
        }
      }
      throw err;
    }
  }

  async signin(dto: AuthDto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if the user doesnt exist, throw exception
    if (!user) {
      throw new ForbiddenException('User does not exist');
    }
    // compare the password
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if the passwword incorrect, throw exception
    if (!pwMatches) {
      throw new ForbiddenException('Password is incorrect');
    }

    // if the passwords match, return the user
    delete user.hash;
    return user;
  }
}
