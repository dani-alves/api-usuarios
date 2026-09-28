require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const z = require("zod");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();
app.use(express.json());

// Servir arquivos estáticos
app.use("/uploads", express.static("uploads"));

// ========== VARIÁVEIS DE AMBIENTE ==========
const SECRET = process.env.SECRET || "chave_padrao_desenvolvimento";
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";

// ========== MULTER - CONFIGURAÇÃO DE UPLOAD ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync("uploads")) {
      fs.mkdirSync("uploads");
    }
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    cb(null, `${timestamp}${ext}`);
  }
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    // Só aceita imagens
    const tipos = /jpeg|jpg|png|gif/;
    const ext = tipos.test(path.extname(file.originalname).toLowerCase());
    const mimetype = tipos.test(file.mimetype);

    if (mimetype && ext) {
      return cb(null, true);
    } else {
      cb(new Error("Apenas imagens são permitidas"));
    }
  }
});

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

// ========== MIDDLEWARE: Logar Requisições ==========
const logarRequisicao = (req, res, next) => {
  const timestamp = new Date().toLocaleString("pt-BR");
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
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
app.post("/login", logarRequisicao, catchAsync(async (req, res) => {
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
app.get("/perfil", logarRequisicao, catchAsync(verificarToken), catchAsync((req, res) => {
  res.json({
    mensagem: `Olá ${req.usuario.email}!`,
    usuario: req.usuario
  });
}));

// Criar usuário
app.post(
  "/usuarios",
  logarRequisicao,
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

// Upload de foto de perfil
app.post(
  "/usuarios/:id/foto",
  logarRequisicao,
  catchAsync(verificarToken),
  upload.single("foto"),
  catchAsync(async (req, res) => {
    const id = parseInt(req.params.id);

    if (isNaN(id)) {
      throw new AppError("ID deve ser um número", 400);
    }

    if (!req.file) {
      throw new AppError("Nenhuma imagem foi enviada", 400);
    }

    const usuario = await prisma.usuario.findUnique({
      where: { id }
    });

    if (!usuario) {
      throw new AppError("Usuário não encontrado", 404);
    }

    // Deleta foto antiga se existir
    if (usuario.fotoPerfil) {
      const caminhoAntigo = path.join(__dirname, usuario.fotoPerfil);
      if (fs.existsSync(caminhoAntigo)) {
        fs.unlinkSync(caminhoAntigo);
      }
    }

    // Salva novo caminho da foto
    const caminhoFoto = `uploads/${req.file.filename}`;

    const usuarioAtualizado = await prisma.usuario.update({
      where: { id },
      data: { fotoPerfil: caminhoFoto },
      select: {
        id: true,
        email: true,
        idade: true,
        telefone: true,
        fotoPerfil: true,
        role: true
      }
    });

    res.json({ mensagem: "Foto atualizada!", usuario: usuarioAtualizado });
  })
);

// Listar usuários COM PAGINAÇÃO
app.get("/usuarios", logarRequisicao, catchAsync(verificarToken), catchAsync(verificarAdmin), catchAsync(async (req, res) => {
  // Pega parâmetros da query
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  // Valida
  if (page < 1) {
    throw new AppError("Página deve ser >= 1", 400);
  }

  if (limit < 1 || limit > 100) {
    throw new AppError("Limit deve estar entre 1 e 100", 400);
  }

  // Calcula skip
  const skip = (page - 1) * limit;

  // Busca usuarios e total
  const [usuarios, total] = await Promise.all([
    prisma.usuario.findMany({
      skip,
      take: limit,
      select: {
        id: true,
        email: true,
        idade: true,
        telefone: true,
        fotoPerfil: true,
        role: true
      }
    }),
    prisma.usuario.count()
  ]);

  // Calcula total de páginas
  const totalPaginas = Math.ceil(total / limit);

  res.json({
    data: usuarios,
    paginacao: {
      pagina: page,
      limit,
      total,
      totalPaginas,
      temProxima: page < totalPaginas,
      temAnterior: page > 1
    }
  });
}));
// Deletar usuário
app.delete(
  "/usuarios/:id",
  logarRequisicao,
  catchAsync(verificarToken),
  catchAsync(verificarAdmin),
  catchAsync(async (req, res) => {
    const id = parseInt(req.params.id);

    if (isNaN(id)) {
      throw new AppError("ID deve ser um número", 400);
    }

    const usuario = await prisma.usuario.findUnique({
      where: { id }
    });

    if (!usuario) {
      throw new AppError("Usuário não encontrado", 404);
    }

    // Deleta foto se existir
    if (usuario.fotoPerfil) {
      const caminho = path.join(__dirname, usuario.fotoPerfil);
      if (fs.existsSync(caminho)) {
        fs.unlinkSync(caminho);
      }
    }

    await prisma.usuario.delete({
      where: { id }
    });

    res.json({ mensagem: "Usuário deletado!" });
  })
);

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

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
});
