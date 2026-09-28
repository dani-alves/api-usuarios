const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Iniciando seed...");

  // Limpa usuários antigos (opcional, mas útil para testes)
  await prisma.usuario.deleteMany();


   // Usuário ADMIN
  const admin = await prisma.usuario.create({
    data: {
      nome: "Admin User",
      email: "admin@test.com",
      idade: 25,
      telefone: "31999999999",
      senha: await bcrypt.hash("admin123", 10),
      role: "admin",
    },
  });

  // Cria 2 usuários de teste
  const usuario1 = await prisma.usuario.create({
    data: {
      email: "joao@test.com",
      idade: 25,
      telefone: "31999999999",
      senha: await bcrypt.hash("senha123", 10),
      
    },
  });

  const usuario2 = await prisma.usuario.create({
    data: {
      email: "maria@test.com",
      idade: 30,
      telefone: "31988888888",
      senha: await bcrypt.hash("senha456", 10),
    },
  });

  console.log("✅ Seed concluído!");
  console.log("Usuários criados:", usuario1, usuario2);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
