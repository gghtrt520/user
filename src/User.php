<?php
namespace common\models;

use Yii;
use yii\base\NotSupportedException;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\web\IdentityInterface;

/**
 * User model
 *
 * @property integer $id
 * @property string $username
 * @property string $password_hash
 * @property string $password_reset_token
 * @property string $email
 * @property string $auth_key
 * @property integer $status
 * @property integer $created_at
 * @property integer $updated_at
 * @property string $password write-only password
 */
class User extends ActiveRecord implements IdentityInterface
{
    const STATUS_DISABLED = 0;
    const STATUS_DELETED = 1;
    const STATUS_ACTIVE = 10;

    public $repassword;
    public $userinitpassword;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%user}}';
    }

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return [
            TimestampBehavior::className(),
        ];
    }

    public function beforeSave($insert)
    {
        if (parent::beforeSave($insert)) {
            if ($this->isNewRecord) {
                $this->auth_key = \Yii::$app->security->generateRandomString();
            }
            return true;
        }
        return false;
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['username','email','repassword'],'required'],
            ['username','uniqueCheck'],
            ['password_hash','required','message'=>Yii::t('app', 'Password cannot be empty')],
            [['lastlogin_at'], 'integer'],
            ['email','match','pattern'=>'/^([a-z0-9]+([._\-]*[a-z0-9])*@([a-z0-9]+[-a-z0-9]*[a-z0-9]+.){1,63}[a-z0-9]+$)/i'],
            ['username','match','pattern'=>'/^[a-zA-Z0-9_]{1,16}$/','message'=> Yii::t('yii', '{attribute}').Yii::t('app', 'must be number or letter')],
            [['username','email','password_hash'],'trim'],
            ['status', 'default', 'value' => self::STATUS_ACTIVE],
            ['status', 'in', 'range' => [self::STATUS_ACTIVE, self::STATUS_DISABLED]],
            ['deleted', 'default', 'value' =>0],
            ['repassword', 'compare', 'compareAttribute' => 'password_hash','message'=>Yii::t('app', 'Passwords do not match')],
        ];
    }

    /**
     * @inheritdoc
     */
    public static function findIdentity($id)
    {
        return static::findOne(['id' => $id, 'status' => self::STATUS_ACTIVE]);
    }

    /**
     * @inheritdoc
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        throw new NotSupportedException('"findIdentityByAccessToken" is not implemented.');
    }

    /**
     * Finds user by username
     *
     * @param string $username
     * @return static|null
     */
    public static function findByUsername($username)
    {
        return static::findOne(['username' => $username, 'status' => self::STATUS_ACTIVE,'deleted'=>0]);
    }

    /**
     * Finds user by password reset token
     *
     * @param string $token password reset token
     * @return static|null
     */
    public static function findByPasswordResetToken($token)
    {
        if (!static::isPasswordResetTokenValid($token)) {
            return null;
        }

        return static::findOne([
            'password_reset_token' => $token,
            'status' => self::STATUS_ACTIVE,
        ]);
    }

    /**
     * Finds out if password reset token is valid
     *
     * @param string $token password reset token
     * @return bool
     */
    public static function isPasswordResetTokenValid($token)
    {
        if (empty($token)) {
            return false;
        }

        $timestamp = (int) substr($token, strrpos($token, '_') + 1);
        $expire = Yii::$app->params['user.passwordResetTokenExpire'];
        return $timestamp + $expire >= time();
    }

    /**
     * @inheritdoc
     */
    public function getId()
    {
        return $this->getPrimaryKey();
    }

    /**
     * @inheritdoc
     */
    public function getAuthKey()
    {
        return $this->auth_key;
    }

    /**
     * @inheritdoc
     */
    public function validateAuthKey($authKey)
    {
        return $this->getAuthKey() === $authKey;
    }

    /**
     * Validates password
     *
     * @param string $password password to validate
     * @return bool if password provided is valid for current user
     */
    public function validatePassword($password)
    {
        return Yii::$app->security->validatePassword($password, $this->password_hash);
    }

    /**
     * Generates password hash from password and sets it to the model
     *
     * @param string $password
     */
    public function setPassword($password)
    {
        $this->password_hash = Yii::$app->security->generatePasswordHash($password);
    }

    /**
     * Generates "remember me" authentication key
     */
    public function generateAuthKey()
    {
        $this->auth_key = Yii::$app->security->generateRandomString();
    }

    /**
     * Generates new password reset token
     */
    public function generatePasswordResetToken()
    {
        $this->password_reset_token = Yii::$app->security->generateRandomString() . '_' . time();
    }

    /**
     * Removes password reset token
     */
    public function removePasswordResetToken()
    {
        $this->password_reset_token = null;
    }

    /**
     * 设置用户身份
     * @作者     止水
     * @编写时间   2017-08-07T14:24:15+0800
     * @版本      1.0
     * @param    integer                   $type 身份类型 1代表init 2代表admin 3代表teacher 4代表student
     */
    public function setRole($type)
    {
        $this->role = $type;
    }

    /**
     * 得到用户类型
     * @作者   止水 
     * @编写时间   2017-08-07T14:29:20+0800
     * @版本      1.0
     * @return   integer                   身份类型 1代表init 2代表admin 3代表teacher 4代表student
     */
    public function getRole()
    {
        return $this->role;
    }

    /**
     * 设置删除状态
     * @作者   止水
     * @编写时间 2017-08-07T15:17:04+0800
     * @版本   1.0
     */
    public function setDeleted()
    {
        $this->deleted = self::STATUS_DELETED;
    }
    /**
     * 用户属性标签
     * @作者     止水
     * @编写时间   2017-08-07T14:33:32+0800
     * @版本     1.0
     * @return array                   数据数组
     */
     public function attributeLabels()
    {
        return [
            'id' => Yii::t('app','ID'),
            'username' => Yii::t('app','Username'),
            'email' => Yii::t('app','Email'),
            'repassword' => Yii::t('app','repassword'),
        ];
    }

    public function uniqueCheck($attribute, $params){
        if($this->isNewRecord){
            $count_create = Static::find()->where(['username'=>$this->$attribute,'deleted_at'=>0])->count(); 
            if($count_create>0){
                $this->addError($attribute, Yii::t('app','Username is already taken')); 
            }  
        }
        else{
            $count_update = Static::find()->where(['username'=>$this->$attribute,'deleted_at'=>0])->andWhere(['not in','id',$this->id])->count();
            if($count_update>0){
                $this->addError($attribute, Yii::t('app','Username is already taken'));
            }             
        }
    }

    /**
     * 登录时间
     */
    public static function ExitLogin(){
        if(!Yii::$app->user->isGuest){
            $user = self::findOne(['id'=>Yii::$app->user->id]);
            $user['lastlogin_at'] = time();
            $user->save();
        }
    }


    /**
     * 关联学生信息表数据
     * @return [type] [description]
     */
    public function getUserProfile(){
        return $this->hasOne(UserProfile::className(),['user_id'=>'id']);
    }


    /**
     * 获取关联班级表数据
     * @return [type] [description]
     */
    public function getClasses()
    {
        return $this->hasOne(Classes::className(),['id'=>'classes_id'])->via('userProfile');
    }
}
