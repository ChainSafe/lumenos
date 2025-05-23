package fhe

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type RingSwitch struct {
	params        *bgv.Parameters
	paramsNew     *bgv.Parameters
	skNew         *rlwe.SecretKey
	RingSwitchEvk *rlwe.EvaluationKey
	ParamsLit     bgv.ParametersLiteral
}

func NewRingSwitchClient(backend *ClientBFV, logN int) (*RingSwitch, error) {
	paramsOld := backend.GetParameters()
	sk := backend.SecretKey()
	// Crucial to use the same moduli
	// qs, ps := make([]uint64, len(paramsFHE.Q())), make([]uint64, len(paramsFHE.P()))
	// for i, qi := range paramsFHE.Q() {
	// 	qs[i] = qi
	// }
	// for i, pi := range paramsFHE.P() {
	// 	ps[i] = pi
	// }

	// Only take the first modulus
	qs := []uint64{paramsOld.Q()[0]}
	ps := []uint64{}

	paramsLit := bgv.ParametersLiteral{
		LogN:             logN,
		Q:                qs,
		P:                ps,
		PlaintextModulus: paramsOld.PlaintextModulus(),
	}

	paramsNew, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		panic(err)
	}

	skNew := rlwe.NewKeyGenerator(paramsNew).GenSecretKeyNew()
	lvlQ := paramsOld.MaxLevel()
	lvlP := paramsOld.MaxLevelP()
	base := 13
	ringSwitchEvk := rlwe.NewKeyGenerator(paramsOld).GenEvaluationKeyNew(
		sk, skNew,
		rlwe.EvaluationKeyParameters{
			LevelQ:               &lvlQ,
			LevelP:               &lvlP,
			BaseTwoDecomposition: &base,
		},
	)
	return &RingSwitch{paramsOld, &paramsNew, skNew, ringSwitchEvk, paramsLit}, nil
}

func (rs *RingSwitch) NewClient(backend *ClientBFV) *ClientBFV {
	paramsNew := rs.paramsNew
	skNew := rs.skNew
	encoder := bgv.NewEncoder(*paramsNew)
	encryptor := rlwe.NewEncryptor(*paramsNew, skNew)
	decryptor := rlwe.NewDecryptor(*paramsNew, skNew)
	evaluator := bgv.NewEvaluator(*paramsNew, nil)
	return &ClientBFV{
		ptField:   backend.ptField,
		paramsFHE: *paramsNew,
		Encoder:   encoder,
		Encryptor: encryptor,
		Decryptor: decryptor,
		Evaluator: evaluator,
	}
}

func (rs *RingSwitch) RingSwitch(ct *rlwe.Ciphertext, backend *ClientBFV) (*rlwe.Ciphertext, error) {
	// for ct.Level() > 0 {
	// 	backend.Rescale(ct, ct)
	// }

	ct2 := rlwe.NewCiphertext(rs.paramsNew, 1, rs.paramsNew.MaxLevel())
	if ct.IsBatched {
		// TODO: dft.SlotsToCoeffsNew(ct, nil, SlotsToCoeffsMatrix)
		// ct.IsBatched = false
	}
	if err := backend.ApplyEvaluationKey(ct, rs.RingSwitchEvk, ct2); err != nil {
		panic(err)
	}

	return ct2, nil
}

type RingSwitchServer struct {
	ringSwitchEvk *rlwe.EvaluationKey
	paramsNew     bgv.Parameters
}

func NewRingSwitchServer(ringSwitchEvk *rlwe.EvaluationKey, paramsLit bgv.ParametersLiteral) (*RingSwitchServer, error) {
	paramsNew, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		return nil, err
	}
	return &RingSwitchServer{ringSwitchEvk, paramsNew}, nil
}

func (rs *RingSwitchServer) RingSwitchNew(ct *rlwe.Ciphertext, backend *ServerBFV) (*rlwe.Ciphertext, error) {
	ct2 := rlwe.NewCiphertext(rs.paramsNew, 1, rs.paramsNew.MaxLevel())
	if err := backend.ApplyEvaluationKey(ct, rs.ringSwitchEvk, ct2); err != nil {
		panic(err)
	}

	return ct2, nil
}
