import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

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
            select: {
                id: true,
                email: true,
                createdAt: true,
                updatedAt: true,
            },
        });
        
        // return the saved user
        return user;
    } catch (err) {
        throw err;
    }
  }

  signin() {
    return 'you are signed in';
  }
}
