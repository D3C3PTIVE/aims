package host



import (
	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)



// BeforeCreate - GORM-specific autogenerated helpers.
func (process *ProcessORM) BeforeCreate(tx *gorm.DB) (err error) {
    id, err := uuid.NewV4()
	if err != nil {
		return err
	}
    process.Id = id.String()

    return nil
}


