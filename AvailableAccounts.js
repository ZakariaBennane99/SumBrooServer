import { Schema, model } from "mongoose";


const AvAccountsSchema = new Schema({
    accounts: {
        type: [String]
    }
});

let AvAc;
try {
    AvAc = model('avac');
} catch {
    AvAc = model('avac', AvAccountsSchema);
}

export default AvAc;
