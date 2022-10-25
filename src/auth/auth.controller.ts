import { Body, Controller, Post, ValidationPipe } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto";


@Controller('auth')
export class AuthController{
    constructor(private authService: AuthService){}

    @Post('signin')
    login(@Body() dto: AuthDto){
        return this.authService.signin(dto);
    }

    @Post('signup')
    signup(@Body(new ValidationPipe()) dto: AuthDto){
        return this.authService.signup(dto);
    }
}