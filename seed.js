const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Iniciando seed...");

  // Limpa usuários antigos
  await prisma.usuario.deleteMany();

  // Usuário ADMIN
  const admin = await prisma.usuario.create({
    data: {
      email: "admin@test.com",
      idade: 25,
      telefone: "31999999999",
      senha: await bcrypt.hash("admin123", 10),
      role: "admin",
    },
  });

  // Usuário normal 1
  const usuario1 = await prisma.usuario.create({
    data: {
      email: "joao@test.com",
      idade: 25,
      telefone: "31999999999",
      senha: await bcrypt.hash("senha123", 10),
      role: "user",
    },
  });

  // Usuário normal 2
  const usuario2 = await prisma.usuario.create({
    data: {
      email: "maria@test.com",
      idade: 30,
      telefone: "31988888888",
      senha: await bcrypt.hash("senha456", 10),
      role: "user",
    },
  });

  console.log("✅ Seed concluído!");
  console.log("Admin:", admin.email);
  console.log("Usuário 1:", usuario1.email);
  console.log("Usuário 2:", usuario2.email);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
