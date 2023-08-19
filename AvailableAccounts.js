import { Schema, model } from "mongoose";


const AvAccountsSchema = new Schema({
    accounts: {
        type: [String]
    }
});

let AvAc;
try {
    AvAc = model('AvAc');
} catch {
    AvAc = model('AvAc', AvAccountsSchema);
}

export default AvAc;
