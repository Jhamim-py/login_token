require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('email-validator');
const cors = require('cors');

const port = 3001;
const app = express();

// Habilitar CORS para todas as origens
app.use(cors());

// Middleware para JSON
app.use(express.json());

// Models
const User = require('./models/User');

// Rota pública
app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Bem vindo' });
});

// Middleware para verificar o token
function checkToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: 'Acesso negado!' });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.SECRET);
    req.user = decodedToken; // Adicionar o ID do usuário ao objeto de solicitação
    next();
  } catch (e) {
    console.error("Erro ao verificar o token:", e);
    res.status(400).json({ msg: 'Token inválido!', error: e.message });
  }
}

// Rota privada
app.get('/user', checkToken, async (req, res) => {
  try {
    // Obter o ID do usuário a partir do token JWT
    const userId = req.user.id;

    // Buscar as informações do usuário pelo ID
    const user = await User.findById(userId, '-senha');

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado" });
    }

    // Se o usuário existe, enviar os dados, excluindo a senha
    res.status(200).json(user);
  } catch (error) {
    // Se ocorrer algum erro durante a busca, enviar uma resposta de erro
    console.error("Erro ao buscar usuário:", error);
    res.status(500).json({ msg: "Erro ao buscar usuário" });
  }
});

// Registro de usuário
app.post('/register', async (req, res) => {
  const { nome, sobrenome, email, senha } = req.body;

  // Validações
  if (!nome || !sobrenome || !email || !senha) {
    return res.status(422).json({ msg: "É obrigatório preencher todos os dados para o login" });
  }

  if (!validator.validate(email)) {
    return res.status(422).json({ msg: "Email inválido" });
  }

  // Checar se já existe o usuário
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ msg: "Usuário já existente, coloque outro email" });
  }

  // Criar senha
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(senha, salt);

  // Criar usuário
  const user = new User({
    nome,
    sobrenome,
    email,
    senha: passwordHash
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso" });
  } catch (erro) {
    res.status(500).json({ msg: "Erro no servidor, tente novamente mais tarde" });
  }
});

// Deletar usuário
app.delete('/delete', checkToken, async (req, res) => {
  const userId = req.user.id;
  const user = await User.findByIdAndDelete(userId);
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }
  res.status(200).json({ msg: "Usuário excluído com sucesso!" });
});

// Login de usuário
app.post('/login', async (req, res) => {
  const { nome, email, senha } = req.body;

  // Validação
  if (!nome || !email || !senha) {
    return res.status(422).json({ msg: "É obrigatório preencher todos os dados para o login" });
  }

  // Checar se existe
  const user = await User.findOne({ nome: nome });

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }

  if (user.email !== email) {
    return res.status(422).json({ msg: "Email inválido" });
  }

  // Checar se a senha corresponde
  const checkPassword = await bcrypt.compare(senha, user.senha);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      { id: user._id },
      secret,
    );
    res.status(200).json({ msg: "Autenticação realizada com sucesso", token });
  } catch (erro) {
    res.status(500).json({ msg: "Erro no servidor, tente novamente mais tarde" });
  }
});

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.ujde7oz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
  .then(() => {
    app.listen(port, () => {
      console.log(`Servidor rodando na porta ${port}`);
      console.log('Conectado ao mongoDB');
    });
  })
  .catch((err) => console.log(err));

