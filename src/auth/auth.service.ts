import { ForbiddenException, Injectable } from "@nestjs/common";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaService } from "src/prisma/prisma.service";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";


@Injectable({})
export class AuthService{

    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService,
        private config: ConfigService
        ){}

    async signup(dto: AuthDto){
     
        try{
            const hash = await argon.hash(dto.password);
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash
                }
            })
            delete user.hash
            return user;
        }
        catch(error){
            if(error instanceof PrismaClientKnownRequestError){
                if(error.code === 'P2002'){
                    throw new ForbiddenException(
                        'Credentials taken'
                    )
                }
            }
            throw error;
        }
     
    }

    async signin(dto: AuthDto): Promise<any>{
        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email
            },
        });
        if(!user) throw new ForbiddenException('Credentials incorrect');
        const pwMatches = await argon.verify(user.hash, dto.password)

        if(!pwMatches){
            throw new ForbiddenException(
                'Credentials incorrect',
            )
        }
          
        return this.signToken(user.id, user.email)
    }

    async signToken(
        userId: number, 
        email: string
        ): Promise<{access_token: string}>{
        const payload = {
            sub: userId,
            email
        };
        const secret = this.config.get('JWT_SECRET')
        const token = await this.jwt.signAsync(
            payload, 
            {
            expiresIn: '15m',
            secret : secret
            }
        );
        return {
            access_token : token
        };
    }
}