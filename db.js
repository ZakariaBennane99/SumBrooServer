import { connect } from 'mongoose'
import dotenv from 'dotenv';
dotenv.config()


const connectDB = async () => {
    try {
      await connect(process.env.MONGODB_URI)
      console.log('MongoDB Connected...')
    } catch (err) {
      console.error(err.message)
      // Exit process with failure
      process.exit(1)
    }
  }

export default connectDB
