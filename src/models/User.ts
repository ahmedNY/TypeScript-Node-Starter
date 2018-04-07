import bcrypt from "bcrypt-nodejs";
import crypto from "crypto";
import { Entity, PrimaryGeneratedColumn, Column, BeforeInsert, BeforeUpdate, ManyToMany, JoinTable } from "typeorm";
import { Category } from "./Category";
import { timeout } from "async";

@Entity()
export class UmUser {

  @PrimaryGeneratedColumn()
  id: number;

  @Column({unique: true})
  email: string;

  @Column()
  password: string;

  @Column({nullable: true})
  passwordResetToken: string;

  @Column({nullable: true})
  passwordResetExpires: number;

  @Column({ nullable: true })
  facebook: string;

  @Column({ nullable: true })
  facebookToken: string;

  @Column({nullable: true})
  twitter: string;

  @Column({nullable: true})
  google: string;

  @Column({nullable: true})
  name: string;

  @Column({nullable: true})
  gender: string;

  @Column({nullable: true})
  location: string;

  @Column({nullable: true})
  website: string;

  @Column({nullable: true})
  picture: string;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    const user = this;
    this.password = await new Promise<string>((resolve, reject) => {
      bcrypt.genSalt(10, (err, salt) => {
        if (err) { reject(err); }
        bcrypt.hash(user.password, salt, undefined, (err: Error, hash) => {
          if (err) { reject(err); }
          resolve(hash);
        });
      });
    });
  }
  comparePassword(candidatePassword: string, cb: (err: Error, isMatch: boolean) => void) {
    bcrypt.compare(candidatePassword, this.password, (err: Error, isMatch: boolean) => {
      cb(err, isMatch);
    });
  }

  gravatar (size: number) {
    if (!size) {
      size = 200;
    }
    if (!this.email) {
      return `https://gravatar.com/avatar/?s=${size}&d=retro`;
    }
    const md5 = crypto.createHash("md5").update(this.email).digest("hex");
    return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
  }
}
