import express from 'express'
import dotenv from 'dotenv'
import cors from 'cors'
import database from './config/database.js'
import { authRouter } from './userroutes/authRouter.js'
import errorController from './middleware/errorController.js'
import cookieParser from 'cookie-parser'

dotenv.config()
database()
const app=express()
app.use(express.json());
app.use(cookieParser());
app.use(cors(
    {
        origin: 'https://frondend-react-opal.vercel.app',
        credentials: true
    }
))

app.use('/User',authRouter)

app.use(errorController)

app.listen(process.env.PORT,()=>{
    console.log("server is runing port "+process.env.PORT)
})