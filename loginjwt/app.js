require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require ('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('email-validator');

const cors = require('cors');

const app = express();


app.use(cors());

app.use(express.json());

//Models
const User = require('./models/User');

//Rota publica

app.get('/', (req,res) =>{
    res.status(200).json({msg:'Bem vindo'})
})

//Rota privada

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
  

app.post('/register', async(req,res) => {
    
    const {nome,sobrenome,email,senha} = req.body

    //validações

    if(!nome || !sobrenome || !email || !senha){
        return res.status(422).json({msg:"É obrigatório preencher todos os dados para o login"})
    }

   verificacao = validator.validate(email) 
    if(verificacao == false){
        return res.status(422).json({msg:"Email inválido"})
    }


    //checar se já existe o usuario
    const userExists = await User.findOne({email:email})

    if(userExists){
        return res.status(422).json({msg:"Usuário já existente, coloque outro email"})
    }

    //criar senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(senha,salt)

    //criar usuario

    const user = new User({
        nome,
        sobrenome,
        email,
        senha: passwordHash,
        tipo,
    })

    try{
        await user.save()
        res.status(201).json({msg:"Usuário criado com sucesso"})
    }
    catch(erro){
        res.status(500).json({msg:"Erro no servidor,tente novamente mais tarde"})
    }
})

app.delete('/delete', checkToken ,async(req,res) =>{
  const userId = req.user.id;
  const user = await User.findByIdAndDelete(userId);
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }
  // Se o usuário existe, enviar os dados, excluindo a senha
  res.status(200).json(user);
  res.status(200).json({msg:"Usuario excluido com sucesso!"})
  return ;
})


//Login  User

app.post('/login', async (req,res) =>{
    const{nome,email,senha} = req.body
    //validação
    if(!nome ||!email || !senha){
        return res.status(422).json({msg:"É obrigatório preencher todos os dados para o login"})
    }
 
    //checar se existe

    const user = await User.findOne({nome:nome})

    if(!user){
        return res.status(404).json({msg:"Usuário não encontrado"})
    }


 
  
    if(user.email != email){
      return res.status(422).json({msg:"email inválido"})
    }

    //checar se é a senha correspondente

    const checkPassword = await bcrypt.compare(senha,user.senha)

    if(!checkPassword){
        return res.status(422).json({msg:"Senha inválida"})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,
        },
    secret,
)
    res.status(200).json({msg:"Autenticação realizada com sucesso",token})
    }
    catch(erro){
        res.status(500).json({msg:"Erro no servidor,tente novamente mais tarde"})
    }
})


const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.ujde7oz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(() => {
    app.listen(3000)
    console.log('Conectado ao mongoDB')
})
.catch((err) => console.log(err));



