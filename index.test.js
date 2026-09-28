const request = require("supertest");
const express = require("express");
const jwt = require("jsonwebtoken");
const z = require("zod");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { PrismaClient } = require("@prisma/client");

// Importe seu app (você precisa exportar ele no index.js)
// const app = require("./index");

// Para testes, vamos criar um app de teste simplificado
const app = express();
const prisma = new PrismaClient();
app.use(express.json());
app.use("/uploads", express.static("uploads"));

const SECRET = "chave_teste_secreta";

// ========== CLASSE DE ERRO ==========
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
  }
}

// ========== SCHEMAS ZOD ==========
const loginSchema = z.object({
  email: z.string().email("Email inválido"),
  senha: z.string().min(6, "Senha deve ter no mínimo 6 caracteres")
});

const criarUsuarioSchema = z.object({
  email: z.string().email("Email inválido"),
  idade: z.number().int("Idade deve ser um número inteiro").min(18, "Deve ter 18+ anos"),
  telefone: z.string().regex(/^\d{11}$/, "Telefone deve ter exatamente 11 dígitos"),
  senha: z.string().min(6, "Senha deve ter no mínimo 6 caracteres")
});

// ========== WRAPPER PARA CAPTURAR ERROS ==========
const catchAsync = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ========== MIDDLEWARE: Verificar Token ==========
const verificarToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    throw new AppError("Token não fornecido", 401);
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.usuario = decoded;
    next();
  } catch (err) {
    throw new AppError("Token inválido ou expirado", 401);
  }
};

// ========== MIDDLEWARE: Verificar Admin ==========
const verificarAdmin = (req, res, next) => {
  if (req.usuario.role !== "admin") {
    throw new AppError("Acesso negado — apenas admin", 403);
  }
  next();
};

// ========== ROTAS ==========

// Login
app.post("/login", catchAsync(async (req, res) => {
  const resultado = loginSchema.safeParse(req.body);

  if (!resultado.success) {
    throw new AppError(resultado.error.issues[0].message, 400);
  }

  const { email, senha } = resultado.data;
  
  const usuario = await prisma.usuario.findUnique({
    where: { email }
  });

  if (!usuario) {
    throw new AppError("Email não encontrado", 401);
  }

  const senhaValida = await bcrypt.compare(senha, usuario.senha);

  if (!senhaValida) {
    throw new AppError("Senha incorreta", 401);
  }

  const token = jwt.sign(
    { id: usuario.id, email: usuario.email, role: usuario.role },
    SECRET,
    { expiresIn: "1h" }
  );

  res.json({ mensagem: "Login bem-sucedido!", token });
}));

// Perfil (protegido)
app.get("/perfil", catchAsync(verificarToken), catchAsync((req, res) => {
  res.json({
    mensagem: `Olá ${req.usuario.email}!`,
    usuario: req.usuario
  });
}));

// Criar usuário
app.post(
  "/usuarios",
  catchAsync(verificarToken),
  catchAsync(verificarAdmin),
  catchAsync(async (req, res) => {
    const resultado = criarUsuarioSchema.safeParse(req.body);

    if (!resultado.success) {
      throw new AppError(resultado.error.issues[0].message, 400);
    }

    const { email, idade, telefone, senha } = resultado.data;

    const senhaHash = await bcrypt.hash(senha, 10);

    const novoUsuario = await prisma.usuario.create({
      data: {
        email,
        idade,
        telefone,
        senha: senhaHash,
        role: "user"
      }
    });

    const { senha: _, ...usuarioSemSenha } = novoUsuario;

    res.json({ mensagem: "Usuário criado!", usuario: usuarioSemSenha });
  })
);

// Listar usuários
app.get("/usuarios", catchAsync(verificarToken), catchAsync(verificarAdmin), catchAsync(async (req, res) => {
  const usuarios = await prisma.usuario.findMany({
    select: {
      id: true,
      email: true,
      idade: true,
      telefone: true,
      fotoPerfil: true,
      role: true
    }
  });
  res.json(usuarios);
}));

// ========== MIDDLEWARE GLOBAL DE ERRO ==========
app.use((err, req, res, next) => {
  console.error(`❌ Erro: ${err.message}`);

  const statusCode = err.statusCode || 500;
  const message = err.message || "Erro interno do servidor";

  res.status(statusCode).json({
    erro: message,
    status: statusCode
  });
});

// ========== TESTES COM JEST ==========

describe("Testes da API", () => {
  beforeAll(async () => {
    const senha = await bcrypt.hash("123456", 10);

    await prisma.usuario.upsert({
      where: { email: "dani@gmail.com" },
      update: { senha, idade: 25, telefone: "31999999999", role: "admin" },
      create: {
        email: "dani@gmail.com",
        idade: 25,
        telefone: "31999999999",
        senha,
        role: "admin"
      }
    });
  });

  // Teste 1: Login com credenciais corretas
  test("POST /login com email e senha corretos retorna 200 e token", async () => {
    const response = await request(app)
      .post("/login")
      .send({
        email: "dani@gmail.com",
        senha: "123456"
      });

    expect(response.status).toBe(200);
    expect(response.body.token).toBeDefined();
    expect(response.body.mensagem).toBe("Login bem-sucedido!");
  });

  // Teste 2: Login com email inexistente
  test("POST /login com email inexistente retorna 401", async () => {
    const response = await request(app)
      .post("/login")
      .send({
        email: "inexistente@gmail.com",
        senha: "123456"
      });

    expect(response.status).toBe(401);
    expect(response.body.erro).toBe("Email não encontrado");
  });

  // Teste 3: Login com senha incorreta
  test("POST /login com senha incorreta retorna 401", async () => {
    const response = await request(app)
      .post("/login")
      .send({
        email: "dani@gmail.com",
        senha: "senhaerrada"
      });

    expect(response.status).toBe(401);
    expect(response.body.erro).toBe("Senha incorreta");
  });

  // Teste 4: Login sem email
  test("POST /login sem email retorna 400", async () => {
    const response = await request(app)
      .post("/login")
      .send({
        senha: "123456"
      });

    expect(response.status).toBe(400);
    expect(response.body.erro).toBeDefined();
  });

  // Teste 5: Login com email inválido
  test("POST /login com email inválido retorna 400", async () => {
    const response = await request(app)
      .post("/login")
      .send({
        email: "nao-e-um-email",
        senha: "123456"
      });

    expect(response.status).toBe(400);
    expect(response.body.erro).toBe("Email inválido");
  });

  // Teste 6: Criar usuário sem token retorna 401
  test("POST /usuarios sem token retorna 401", async () => {
    const response = await request(app)
      .post("/usuarios")
      .send({
        email: "novo@gmail.com",
        idade: 25,
        telefone: "31987654321",
        senha: "senha123"
      });

    expect(response.status).toBe(401);
    expect(response.body.erro).toBe("Token não fornecido");
  });

  // Teste 7: Perfil sem token retorna 401
  test("GET /perfil sem token retorna 401", async () => {
    const response = await request(app)
      .get("/perfil");

    expect(response.status).toBe(401);
    expect(response.body.erro).toBe("Token não fornecido");
  });

  // Teste 8: Listar usuários retorna array
  test("GET /usuarios com token válido retorna array", async () => {
    // Primeiro faz login pra pegar token
    const loginResponse = await request(app)
      .post("/login")
      .send({
        email: "dani@gmail.com",
        senha: "123456"
      });

    const token = loginResponse.body.token;

    // Depois faz a requisição autenticada
    const response = await request(app)
      .get("/usuarios")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
  });
});

// Fechar conexão com banco após testes
afterAll(async () => {
  await prisma.$disconnect();
});
