import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeleteResult, EntityNotFoundError, Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './user.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  findOneByUsername(username: string): Promise<User> {
    return this.userRepository.findOneBy({ username });
  }

  async findOne(id: number): Promise<User> {
    try {
      return await this.userRepository.findOneByOrFail({ id });
    } catch (error) {
      if (error instanceof EntityNotFoundError) {
        throw new NotFoundException('User not found');
      }
      throw error;
    }
  }

  async create(data: CreateUserDto): Promise<User> {
    const { email, firstName, lastName, username, password } = data;
    const userExists = await this.findOneByUsername(username);
    const emailExists = await this.userRepository.findOneBy({ email });
    if (userExists || emailExists) {
      throw new BadRequestException('Username already exists');
    }
    const user = this.userRepository.create({
      username,
      password,
      email,
      firstName,
      lastName,
    });
    return this.userRepository.save(user);
  }

  async updateRefreshToken(
    userId: number,
    refreshToken: string,
  ): Promise<void> {
    await this.userRepository.update(userId, { refreshToken });
  }

  async remove(id: number): Promise<DeleteResult> {
    return this.userRepository.delete(id);
  }

  async findByEmail(email: string): Promise<User> {
    return this.userRepository.findOneBy({ email });
  }

  async findOneByResetToken(token: string): Promise<User> {
    return this.userRepository
      .createQueryBuilder('user')
      .where('user.resetPasswordToken = :token', { token })
      .getOne();
  }

  async save(user: User): Promise<User> {
    return this.userRepository.save(user);
  }
}
