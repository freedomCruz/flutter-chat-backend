const { response } = require('express');
const bcrypt = require('bcryptjs');

const User = require('../models/usuario.js');
const { generarJWT } = require('../helpers/jwt.js');

const crearUsuario = async (req, res = response) => {

    const {email, password} = req.body;

    try {
        const existeEmail = await User.findOne({email});
        if(existeEmail){
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya esta registrado'
            });
        }
       
        const user = new User(req.body)
        // Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        user.password = bcrypt.hashSync(password, salt);


        await user.save();

        // Generar Json Web Token
        const token = await generarJWT(user.id);

        res.json({
            ok: true,
            user,
            token
        });

    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Error inesperado, contacte con el administrador'
        });
    }
}

const login = async (req, res = response) => {
    const {email, password} = req.body;

    try {
        const userDB = await User.findOne({email});
        if(!userDB){
            return res.status(404).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }

        // Confirmar los passwords
        const validPassword = bcrypt.compareSync(password, userDB.password);
        if(!validPassword){
            return res.status(400).json({
                ok: false,
                msg: 'La contraseña no es valida'
            });
        }

        // Generar Json Web Token
        const token = await generarJWT(userDB.id);

        res.json({
            ok: true,
            userDB,
            token
        });

    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Error inesperado, contacte con el administrador'
        });
    }
}

const renewToken = async (req, res = response) => {
    const uid = req.uid;

    // Generar Json Web Token
    const token = await generarJWT(uid);

    // Obtener el usuario por UID
    const user = await User.findById(uid);

    res.json({
        ok: true,
        user,
        token
    });
}

module.exports = {
    crearUsuario,
    login,
    renewToken
    
}