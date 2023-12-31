const express = require('express');
const path = require('path');
require('dotenv').config();

// DB config
const { dbConnection } = require('./database/config');
dbConnection();


//App de Express
const app = express();

// Lectura y parseo del body
app.use( express.json() );

// node server
const server = require('http').createServer(app);
module.exports.io = require('socket.io')(server);
//Llamar sockets.js
require('./sockets/sockets');


// Path público
const publicPath = path.resolve( __dirname, 'public');
app.use( express.static( publicPath ));

// Mis rutas
app.use('/api/login', require('./routes/auth'));


server.listen( process.env.PORT, (err)  => {
   
    if (err) throw Error(err);

    console.log('Servidor corriendo en puerto..', process.env.PORT )

});