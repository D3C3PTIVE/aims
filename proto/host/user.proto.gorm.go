package host



import (
	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)



// BeforeCreate - GORM-specific autogenerated helpers.
func (user *UserORM) BeforeCreate(tx *gorm.DB) (err error) {
    id, err := uuid.NewV4()
	if err != nil {
		return err
	}
    user.Id = id.String()

    return nil
}



// BeforeCreate - GORM-specific autogenerated helpers.
func (group *GroupORM) BeforeCreate(tx *gorm.DB) (err error) {
    id, err := uuid.NewV4()
	if err != nil {
		return err
	}
    group.Id = id.String()

    return nil
}


