import { Schema, model } from "mongoose";

const MediaContentSchema = new Schema({
    mediaType: {
        type: String,
        enum: ["image", "video", "audio"], // example media types
        required: true
    },
    awsLink: {
        type: String,
        required: true
    }
});

const PinterestTextualDataSchema = new Schema({
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    destinationLink: {
        type: String,
        required: true
    }
});

const TextualDataSchema = new Schema({
    pinterest: PinterestTextualDataSchema,
    // Other platforms' specific schemas can be added here
    // For example:
    // tiktok: TikTokTextualDataSchema,
});

const PostContentSchema = new Schema({
    media: MediaContentSchema,
    textualData: TextualDataSchema
});

const PostSchema = new Schema({
    postStatus: {
        type: String,
        enum: ["in review", "rejected", "published"],
        required: true
    },
    platform: String,
    postLink: String, // for published posts
    postId: String, // for published posts: post ID from the platform API
    publishingDate: Date,
    // before the review, this represents the date at which 
    // user hit publish after the review this should be 
    // updated to the actual publishing date (in case of accepting the post)
    content: PostContentSchema, // after publishing remove the content
    comment: String, // for rejected posts
    analytics: {
        type: Schema.Types.Mixed
    }
});

const SocialMediaLinkSchema = new Schema({
    platformName: {
        type: String,
        required: true
    },
    profileLink: {
        type: String,
        required: true
    }, 
    profileStatus: {
        type: String,
        enum: ["inReview", "pendingPay", "pendingAuth", "active", "canceled", "authExpired"],
        // "New": profile is available to be applied for.
        // "InReview": profile is in review.
        // "Disabled": profile disabled by admin for quality and other issues.(rare case)
        // "Active": profile is fully active. 
        // "Pending": awaiting user payment
        // Settings > Linked Accounts, or he/she can click on the manage billing and pay from there. 
        required: true
        // If rejected, we remove the profile and send him a message on why 
        // we rejected him and that when he fulfills the reqs, he can a send a profile linking req
    }, 
    pricePlans: {
        type: [String]
    },
    description: {
        type: String
    },
    niche: {
        type: String
    },
    lastPublished: {
        type: Date,
        default: null
    },
    audience: {
        type: [String],
        validate: {
            validator: function(array) {
                return array.length <= 10;
            },
            message: 'Audience array size should not exceed 10 tags.'
        }
    },
    accessToken: {
        type: String
    },
    accesstokenExpirationDate: {
        type: Date
    }, 
    refreshToken: {
        type: String
    },
    refreshTokenExpirationDate: {
        type: Date
    },
    posts: [PostSchema]
});

const UserSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    accountStatus: {
        type: String,
        enum: ["inReview", "disabled", "active", "pending"],
        // "inReview": account is being reviewed.
        // "Disabled": account has been disabled by admin for quality and other issues.(rare case)
        // "Active": account is fully active.
        // "Pending": awaiting user payment/onboarding before activation. You'll have to send an email
        // in which you direct them to pay first, then start onboarding. The email link expires after
        // 48H after which the user is deleted from the DB.
        required: true
        // If rejected, we remove the user entirely and send him a message on why 
        // we rejected him and that when he fulfills the reqs, he can create an account again
    }, 
    password: {
        type: String
    },
    initialPlanChosen: {
        type: String
    },
    onboardingStep: {
        type: Number,
        default: 0
    },
    applicationDate: {
        type: String, 
        required: true
    },
    stripeId: {
        type: String,
        unique: true
    },
    socialMediaLinks: [SocialMediaLinkSchema]
});

const User = model("user", UserSchema);
export default User;
