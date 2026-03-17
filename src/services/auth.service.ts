import bcrypt from "bcrypt";
import { prisma } from "../config/database";
import { signToken } from "../utils/jwt";
import type { UserRole } from "../types";

export class AuthService {
  async loginUser(gymId: string, email: string, password: string) {
    const user = await prisma.user.findUnique({
      where: { gymId_email: { gymId, email } },
    });

    if (!user || !user.isActive) {
      throw new Error("Credenciais inválidas");
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new Error("Credenciais inválidas");
    }

    const token = signToken({ sub: user.id, gymId: user.gymId, role: "USER" });

    const { passwordHash: _, ...userData } = user;
    return { token, user: userData };
  }

  async loginProfessional(gymId: string, email: string, password: string) {
    const professional = await prisma.professional.findUnique({
      where: { gymId_email: { gymId, email } },
    });

    if (!professional || !professional.isActive) {
      throw new Error("Credenciais inválidas");
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      professional.passwordHash,
    );
    if (!isPasswordValid) {
      throw new Error("Credenciais inválidas");
    }

    const token = signToken({
      sub: professional.id,
      gymId: professional.gymId,
      role: "PROFESSIONAL",
    });

    const { passwordHash: _, ...professionalData } = professional;
    return { token, professional: professionalData };
  }

  async loginGymAdmin(email: string, password: string) {
    // ⚡ Bolt Optimization: Combined sequential database queries into a single query
    // Previously, this required two sequential roundtrips (Gym then Professional).
    // Using an include allows us to fetch both in a single database operation,
    // reducing latency significantly during admin logins.
    const adminAccount = await prisma.professional.findFirst({
      where: {
        email,
        isActive: true,
        gym: {
          email,
          isActive: true
        }
      },
      include: {
        gym: true
      }
    });

    if (!adminAccount) throw new Error("Credenciais inválidas");

    const isPasswordValid = await bcrypt.compare(
      password,
      adminAccount.passwordHash,
    );

    if (!isPasswordValid) throw new Error("Credenciais inválidas");

    const token = signToken({
      sub: adminAccount.id,
      gymId: adminAccount.gymId,
      role: "GYM_ADMIN",
    });

    const { gym } = adminAccount;

    return { token, gym };
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async changePassword(
    userId: string,
    role: UserRole,
    currentPassword: string,
    newPassword: string,
  ) {
    if (role === "USER") {
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) throw new Error("Usuário não encontrado");
      const isPasswordValid = await bcrypt.compare(
        currentPassword,
        user.passwordHash,
      );
      if (!isPasswordValid) throw new Error("Senha atual inválida");
      const hashedPassword = await this.hashPassword(newPassword);
      await prisma.user.update({
        where: { id: userId },
        data: { passwordHash: hashedPassword },
      });
    } else {
      const prof = await prisma.professional.findUnique({
        where: { id: userId },
      });
      if (!prof) throw new Error("Profissional não encontrado");
      const isPasswordValid = await bcrypt.compare(
        currentPassword,
        prof.passwordHash,
      );
      if (!isPasswordValid) throw new Error("Senha atual inválida");
      const hashedPassword = await this.hashPassword(newPassword);
      await prisma.professional.update({
        where: { id: userId },
        data: { passwordHash: hashedPassword },
      });
    }
  }
}
