import { Mongo } from "../database/mongo.js"
import { ObjectId } from 'mongodb'
import crypto from 'crypto'
import { promisify } from "util";

const pbkdf2Async = promisify(crypto.pbkdf2);
const collectionName = 'users'

export default class UsersDataAccess {
    async getUsers() {
        const result = await Mongo.db
            .collection(collectionName)
            .find({})
            .toArray()

        return result
    }

    async deleteUser(userId) {
        const result = await Mongo.db
            .collection(collectionName)
            .findOneAndDelete({ _id: new ObjectId(userId) })

        return result
    }

    async updateUser(userId, userData) {
        if (userData.password) {
            const salt = crypto.randomBytes(16)

            const hashedPassword = await pbkdf2Async(
                userData.password,
                salt,
                310000,
                16,
                'sha256'
            )

            userData = { ...userData, password: hashedPassword, salt }

            const result = await Mongo.db
                .collection(collectionName)
                .findOneAndUpdate(
                    { _id: new ObjectId(userId) },
                    { $set: userData }
                )

            return result
        } else {
            const result = await Mongo.db
                .collection(collectionName)
                .findOneAndUpdate(
                    { _id: new ObjectId(userId) },
                    { $set: userData }
                )

            return result
        }
    }
}